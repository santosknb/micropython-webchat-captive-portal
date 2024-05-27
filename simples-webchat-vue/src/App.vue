<template>
  <v-app>
    <v-main>


      <v-app-bar color="primary" density="compact">
        <v-app-bar-title>Wifi Chat </v-app-bar-title>

        <template v-slot:append>
          <v-btn>Abrir no navegador</v-btn>
        </template>
      </v-app-bar>

      <v-list :items="items" lines="infinity" item-props class="reverseorder">
        <template v-slot:subtitle="{ subtitle }">
          <div v-html="subtitle"></div>
        </template>
      </v-list>




    </v-main>


    <v-bottom-navigation v-model="activeTab" fixed>
      <v-btn value="photo">
        <span>Foto</span>
        <v-icon>mdi-camera</v-icon>
      </v-btn>
      <v-textarea v-model="message" append-icon="mdi-send" placeholder="Digite sua mensagem" no-resize rows="1"
        variant="solo" shaped @click:append="sendMessage"></v-textarea>



    </v-bottom-navigation>



  </v-app>
</template>

<script>
export default {
  name: 'App',

  data() {
    return {
      activeTab: 'message',
      message: '',
      items: [
        { type: 'subheader', title: 'Today' },
        {
          prependAvatar: 'https://cdn.vuetifyjs.com/images/lists/1.jpg',
          title: 'Brunch this weekend?',
          subtitle: `<span class="text-primary">Ali Connors</span> &mdash; I'll be in your neighborhood doing errands this weekend. Do you want to hang out?`,
        },
        { type: 'divider', inset: true },
        {
          prependAvatar: 'https://cdn.vuetifyjs.com/images/lists/2.jpg',
          title: 'Summer BBQ',
          subtitle: `<span class="text-primary">to Alex, Scott, Jennifer</span> &mdash; Wish I could come, but I'm out of town this weekend.`,
        },
        { type: 'divider', inset: true },
        {
          prependAvatar: 'https://cdn.vuetifyjs.com/images/lists/3.jpg',
          title: 'Oui oui',
          subtitle: '<span class="text-primary">Sandra Adams</span> &mdash; Do you have Paris recommendations? Have you ever been?',
        },
        { type: 'divider', inset: true },
        {
          prependAvatar: 'https://cdn.vuetifyjs.com/images/lists/4.jpg',
          title: 'Birthday gift',
          subtitle: '<span class="text-primary">Trevor Hansen</span> &mdash; Have any ideas about what we should get Heidi for her birthday?',
        },
        { type: 'divider', inset: true },
        {
          prependAvatar: 'https://api.dicebear.com/8.x/initials/svg?seed=01',
          title: 'Anonymous-01',
          subtitle: '<span class="text-primary">Britta Holt</span> &mdash; We should eat this: Grate, Squash, Corn, and tomatillo Tacos.jhjhjhjh jgjhghghjghggjhghgj We should eat this: Grate, Squash, Corn, and tomatillo Tacos.jhjhjhjh jgjhghghjghggjhghgj rate, Squash, Corn, and tomatillo Tacos.jhjhjhjh jgjhghghjghggjhghgj We should eat this: Grate, Squash, Corn, and tomatillo Tacos.jhjhjhjh jgjhghghjghggjhghgj',
        },
      ],
    }
  },

  methods: {
    sendMessage() {
      // Lógica para enviar a mensagem
      console.log('Mensagem enviada:', this.message)
      this.message = ''
    }
  }
}
</script>

<style scoped>
.reverseorder {
  position: absolute;
    bottom: 55px;
}
.logo {
  height: 6em;
  padding: 1.5em;
  will-change: filter;
  transition: filter 300ms;
}

.logo:hover {
  filter: drop-shadow(0 0 2em #646cffaa);
}

.logo.vue:hover {
  filter: drop-shadow(0 0 2em #42b883aa);
}
</style>
