Finally Flags distribution Inc. made a false step! They accidentally exposed their client certificate signing endpoint to the internet... It doesn't seem to be able to sign admin certificates though...

This is a remote challenge, you can connect with:

`openssl s_client -connect flagsdistribution.challs.open.ecsc2024.it:38000`

`nc flagsdistribution.challs.open.ecsc2024.it 38001`