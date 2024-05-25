import gc
import sys
import network
import socket
import uasyncio as asyncio
import ubinascii
import hashlib
import struct
import hashlib
import ubinascii

# Auxiliar para detectar o uasyncio v3
IS_UASYNCIO_V3 = hasattr(asyncio, "__version__") and asyncio.__version__ >= (3,)

# Configurações do ponto de acesso
SERVER_SSID = 'Chat local captive portal'  # máximo de 32 caracteres
SERVER_IP = '10.0.0.1'
SERVER_SUBNET = '255.255.255.0'

def wifi_start_access_point():
    """ Configura o ponto de acesso """
    wifi = network.WLAN(network.AP_IF)
    wifi.active(True)
    wifi.ifconfig((SERVER_IP, SERVER_SUBNET, SERVER_IP, SERVER_IP))
    wifi.config(essid=SERVER_SSID, authmode=network.AUTH_OPEN)
    print('Configuração de rede:', wifi.ifconfig())

def _handle_exception(loop, context):
    """ Somente uasyncio v3: manipulador de exceção global """
    print('Manipulador de exceção global')
    sys.print_exception(context["exception"])
    sys.exit()

class DNSQuery:
    def __init__(self, data):
        self.data = data
        self.domain = ''
        tipo = (data[2] >> 3) & 15  # Bits de Opcode
        if tipo == 0:  # Consulta padrão
            ini = 12
            lon = data[ini]
            while lon != 0:
                self.domain += data[ini + 1:ini + lon + 1].decode('utf-8') + '.'
                ini += lon + 1
                lon = data[ini]
        print("Consulta DNS para o domínio:" + self.domain)

    def response(self, ip):
        print("Resposta DNS para o domínio: {} ==> {}".format(self.domain, ip))
        if self.domain:
            packet = self.data[:2] + b'\x81\x80'
            packet += self.data[4:6] + self.data[4:6] + b'\x00\x00\x00\x00'  # Contagem de perguntas e respostas
            packet += self.data[12:]  # Domínio original da pergunta
            packet += b'\xC0\x0C'  # Ponteiro para o nome de domínio
            packet += b'\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x04'  # Tipo de resposta, ttl e comprimento dos dados do recurso -> 4 bytes
            packet += bytes(map(int, ip.split('.')))  # 4 bytes de IP
        # print(packet)
        return packet

class MyApp:
    def __init__(self):
        self.connected_clients = []
    async def start(self):
        # Obter o loop de eventos
        
        loop = asyncio.get_event_loop()

        # Adicionar manipulador de exceção global
        if IS_UASYNCIO_V3:
            loop.set_exception_handler(_handle_exception)

        # Iniciar o ponto de acesso Wi-Fi
        wifi_start_access_point()

        # Criar o servidor e adicionar tarefa ao loop de eventos
        server = asyncio.start_server(self.handle_http_connection, "0.0.0.0", 80)
        loop.create_task(server)

        # Iniciar a tarefa do servidor WebSocket
        websocket = asyncio.start_server(self.websocket_handler, "0.0.0.0", 8765)
        loop.create_task(websocket)

        # Iniciar a tarefa do servidor DNS
        loop.create_task(self.run_dns_server())

        # Iniciar o loop infinito
        print('Executando em loop infinito...')
        loop.run_forever()

    async def handle_http_connection(self, reader, writer):
        gc.collect()

        # Obter a linha de requisição HTTP
        data = await reader.readline()
        request_line = data.decode()
        addr = writer.get_extra_info('peername')
        print('Recebido {} de {}'.format(request_line.strip(), addr))

        # Ler os cabeçalhos, para satisfazer o cliente (caso contrário, o curl exibe um erro)
        while True:
            gc.collect()
            line = await reader.readline()
            if line == b'\r\n': break

        # Lidar com a requisição
        if len(request_line) > 0:
            response = 'HTTP/1.0 200 OK\r\n\r\n'
            with open('index.html') as f:
                response += f.read()
            await writer.awrite(response)

        # Fechar o socket
        await writer.aclose()
        # print("Socket do cliente fechado")

    async def run_dns_server(self):
        """ Função para lidar com as requisições DNS recebidas """
        udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udps.setblocking(False)
        udps.bind(('0.0.0.0', 53))

        while True:
            try:
                # gc.collect()
                if IS_UASYNCIO_V3:
                    yield asyncio.core._io_queue.queue_read(udps)
                else:
                    yield asyncio.IORead(udps)
                data, addr = udps.recvfrom(4096)
                print("Requisição DNS recebida...")

                DNS = DNSQuery(data)
                udps.sendto(DNS.response(SERVER_IP), addr)

                print("Respondendo: {:s} -> {:s}".format(DNS.domain, SERVER_IP))

            except Exception as e:
                print("Erro no servidor DNS:", e)
                await asyncio.sleep_ms(3000)

        udps.close()

    async def websocket_handler(self, reader, writer):
        self.connected_clients.append(writer) # Adicionar cliente à lista de clientes conectados
        try:
            # Realizar o handshake do WebSocket
            request_line = await reader.readline()
            headers = {}
            while True:
                header = await reader.readline()
                if header == b'\r\n':
                    break
                header_key, header_value = header.decode().strip().split(":", 1)
                headers[header_key.lower()] = header_value.strip()

            if "sec-websocket-key" not in headers:
                print("Nenhuma chave WebSocket encontrada nos cabeçalhos")
                await writer.aclose()
                return

            accept_key = self.generate_accept_key(headers["sec-websocket-key"])
            response = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept_key}\r\n\r\n"
            )
            await writer.awrite(response)

            while True:
                # Ler o quadro do WebSocket
                frame = await reader.read(2)
                if not frame:
                    break

                opcode = frame[0] & 0x0F
                if opcode == 0x8:  # quadro de fechamento da conexão
                    print("Quadro de fechamento recebido")
                    break

                length = frame[1] & 0x7F
                if length == 126:
                    length = int.from_bytes(await reader.read(2), "big")
                elif length == 127:
                    length = int.from_bytes(await reader.read(8), "big")

                masks = await reader.read(4)
                message_bytes = bytearray(await reader.read(length))
                for i in range(len(message_bytes)):
                    message_bytes[i] ^= masks[i % 4]

                message = message_bytes.decode("utf-8")
                print(f"Mensagem recebida: {message}")

                # Ecoar a mensagem de volta
                response = self.create_websocket_frame(message)
                 # Transmitir a mensagem para todos os clientes conectados
                for client_writer in self.connected_clients:
                    try:
                        await client_writer.awrite(response)
                    except Exception as e:
                        print(f"Erro ao escrever para o cliente: {e}")
                

        except Exception as e:
            print("Erro no manipulador do WebSocket:", e)
        finally:
            self.connected_clients.remove(writer)
            await writer.aclose()

    def generate_accept_key(self, key):
        magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        sha1 = hashlib.sha1((key + magic_string).encode())
        return ubinascii.b2a_base64(sha1.digest()).decode('utf-8').strip()

    def create_websocket_frame(self, message):
        message_bytes = message.encode("utf-8")
        length = len(message_bytes)

        if length <= 125:
            header = struct.pack("B", 0x81) + struct.pack("B", length)
        elif length >= 126 and length <= 65535:
            header = struct.pack("B", 0x81) + struct.pack("!H", length)
        else:
            header = struct.pack("B", 0x81) + struct.pack("!Q", length)

        return header + message_bytes

# Ponto de entrada do código principal
try:
    # Instanciar o aplicativo e executar
    myapp = MyApp()

    if IS_UASYNCIO_V3:
        asyncio.run(myapp.start())
    else:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(myapp.start())

except KeyboardInterrupt:
    print('Tchau')

finally:
    if IS_UASYNCIO_V3:
        asyncio.new_event_loop()  # Limpar o estado retido
