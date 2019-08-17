<template>
    <div class="flex min-h-screen">
        <div class="m-auto bg-gray-900 p-4 rounded shadow">
            <form ref="loginForm" class="flex flex-col text-xl" @submit.prevent="login()">
                <div class="text-3xl">Login</div>
                <label for="user">Username</label>
                <input type="text" id="user" name="user" class="text-gray-900">
                <label for="pass">Password</label>
                <input type="text" name="pass" id="pass" class="text-gray-900">
                <button type="submit" class="bg-transparent border border-2 text-orange-500 border-orange-500 rounded mt-4 p-2">SUBMIT</button>
            </form>
        </div>
    </div>
</template>

<script lang="ts">
import {Component, Vue} from 'vue-property-decorator';
import axios from '@/axios';
@Component({})
export default class Home extends Vue {
    public $refs!: {
        loginForm: HTMLFormElement,
    };

    public async login() {
        const data = new FormData(this.$refs.loginForm);
        const resp = await axios.post('/user/login', data);
        if (resp.status === 200) {
            this.$router.push('/projects');
        } else {
            // display error
        }
    }
}
</script>
