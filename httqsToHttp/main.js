const express = require('express');
const { spawn } = require('child_process');

const app = express();
function getHTTQSFile(file, res) {
    // console.log(`\x1b[34m../target/debug/httqs_test.exe --client --silent --file=${file}\x1b[0m`);
    let child = spawn('../target/debug/httqs_test.exe', ['--client', '--silent', '--save', '--file='+file]);
    // child.stdout.on('data', (data) => {
    //     console.log(`\x1b[34mstdout (${file}):\x1b[0m ${data}`);
    //     res.write(data);
    //     res.send();
    // });
    // on close
    child.on('close', (code) => {
        // send the file to the client from httqs_out/{path}
        console.log(`\x1b[34mchild process exited with code ${code}\x1b[0m`);
        console.log(`\x1b[34msending file: ${file}\x1b[0m`)
        res.sendFile(`httqs_out/${file}`, {root: __dirname}, (err) => {
            if (err) {
                console.log("Error sending file: " + err);
                res.send("Error sending file: " + err);
            }
        });
    });
}

app.get('/', (req, res) => {
    // Run ../target/debug/httqsToHttp.exe --client --silent --file=index.html and send the stdout
    console.log("req.url from /: " + req.url);
    getHTTQSFile('index.html', res);
});
app.get("*", (req, res) => {
    // Run ../target/debug/httqsToHttp.exe --client --silent --file=index.html and send the stdout
    // remove a leading slash
    console.log("req.url: " + req.url);
    req.url = req.url.substring(1);
    // if the url ends with "/", send /index.html
    if (req.url.endsWith("/")) {
        req.url += "index.html";
    }
    getHTTQSFile(req.url, res);
});


app.listen(3000, () => {
    console.log('Listening on port 3000!');
});