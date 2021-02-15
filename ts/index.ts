import net = require("net");
import {box} from "tweetnacl";
import {encodeBase64, decodeBase64} from "tweetnacl-util";
import crypt = require("./crypt");

if (process.argv[2] == "server")
{
    const serverSecretKey =
        decodeBase64("YyCF6Oygo9lw+tIg350VV9T86Sl9ICzq2L2r4gwlQ+E=");
    const clientPublicKey =
        decodeBase64("cUiCef9JzKSkDSf1rldaOHNP2cgGXipc4tEk96syGS4=");
    const sharedB = box.before(clientPublicKey, serverSecretKey);
    console.log("starting server");
    const server = net.createServer((c: net.Socket) => {
        console.log("client connected");
        c.setEncoding("utf8");
        c.on("data", (buf: Buffer) => {
            const decrypted = crypt.decrypt(sharedB, buf.toString());
            console.log("received: ", decrypted);
            const encrypted = crypt.encrypt(sharedB, {
                key : "hello",
                value : "from server",
            });
            c.write(encrypted);
        });
        c.on("end", () => {
            console.log("client disconnected");
        });
    });
    server.on("error", (err) => {
        throw err;
    });

    if (process.argv.length > 3)
    {
        server.listen(2679, process.argv[3], () => {
            console.log(`server listening on ${process.argv[3]}`);
        });
    }
    else
    {
        server.listen(2679, "::0", () => {
            console.log("server listening on ::0");
        });
    }
}
else if (process.argv[2] == "client")
{
    const serverPublicKey =
        decodeBase64("cW3T6xW6D128PkrTgP3Os6owHZlRI4eygwaRjbnI4l8=");
    const clientSecretKey =
        decodeBase64("MJFEvM2H8zJisKVPNt6giHvuXBgJPZsGkaginZUFX28=");
    const sharedA = box.before(serverPublicKey, clientSecretKey);

    console.log("starting client");
    var client = new net.Socket();

    client.on("connect", function() {
        console.log("Client: connection established with server");
        const encrypted = crypt.encrypt(sharedA, {
            key : "hello",
            value : "from client",
        });
        client.write(encrypted);
    });

    client.on("data", (buf: Buffer) => {
        const decrypted = crypt.decrypt(sharedA, buf.toString());
        console.log("received: ", decrypted);
    });

    setTimeout(function() {
        client.end("");
    }, 5000);

    if (process.argv.length > 3)
    {
        client.connect({host : process.argv[3], port : 2679});
    }
    else
    {
        client.connect({host : "::1", port : 2679});
    }
}
else
{
    console.log("use 'npm run client' or 'npm run server'\n");
    console.log("running crypt test\n");
    const obj = {hello : "peer"};
    const pairA = crypt.generateKeyPair();
    console.log(
        `const secretKeyA = decodeBase64("${encodeBase64(pairA.secretKey)}");`);
    console.log(
        `const publicKeyA = decodeBase64("${encodeBase64(pairA.publicKey)}");`);
    const pairB = crypt.generateKeyPair();
    console.log(
        `const secretKeyB = decodeBase64("${encodeBase64(pairB.secretKey)}");`);
    console.log(
        `const publicKeyB = decodeBase64("${encodeBase64(pairB.publicKey)}");`);
    const sharedA = box.before(pairB.publicKey, pairA.secretKey);
    const sharedB = box.before(pairA.publicKey, pairB.secretKey);
    const encrypted = crypt.encrypt(sharedA, obj);
    const decrypted = crypt.decrypt(sharedB, encrypted);

    if (decrypted.hello == obj.hello)
    {
        console.log("encrypt/decrypt worked:", decrypted,
                    obj); // should be shallow equal
    }
    else
    {
        console.log("encrypt/decrypt failed:", decrypted, obj);
        console.log({hello : "peer"} == {hello : "peer"});
        console.log({hello : "peer"});
    }
}
