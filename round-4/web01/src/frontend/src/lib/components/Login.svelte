<script lang="ts">
    import { Section, Register } from 'flowbite-svelte-blocks';
    import { Alert, Button, Label, Input } from 'flowbite-svelte';

    let username = "";
    let password = "";
    let msg = "";

    let login = () => {
        fetch(
            "/api/v1/session",
            {
                credentials: "same-origin",
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    "username": username,
                    "password": password,
                }),
            }
        ).then((response) => {
            if (response.status === 200) {
                window.location.reload();
                return;
            }
            msg = "Wrong credentials!";
        });
    }
</script>

<Section name="login">
    <Register href="/">
        <div class="p-6 space-y-4 md:space-y-6 sm:p-8">
        <form class="flex flex-col space-y-6" action="/">
            <Label class="space-y-2">
            <span>Username</span>
            <Input bind:value={username} type="text" name="username" placeholder="username" required />
            </Label>
            <Label class="space-y-2">
            <span>Password</span>
            <Input bind:value={password} id="password" type="password" name="password" placeholder="•••••" required />
            </Label>
            <Button class="w-full1" on:click={login}>Sign in</Button>
        </form>
        {#if msg}
            <Alert color="red">
                {msg}
            </Alert>
        {/if}
        </div>
    </Register>
</Section>
