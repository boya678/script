const fs = require('fs');
const xml2js = require('xml2js');
const https = require('https');
const args = process.argv.slice(2);

// Función para leer y convertir XML a JSON
function convertXMLToJson(xmlFilePath) {
    return new Promise((resolve, reject) => {
        fs.readFile(xmlFilePath, 'utf-8', (err, xmlData) => {
            if (err) {
                reject(err);
            }
            xml2js.parseString(xmlData, { explicitArray: false }, (err, result) => {
                if (err) {
                    reject(err);
                }
                resolve(result);
            });
        });
    });
}

// Función para guardar JSON en un archivo
function saveJsonToFile(jsonData, outputFilePath) {
    return new Promise((resolve, reject) => {
        fs.writeFile(outputFilePath, JSON.stringify(jsonData, null, 2), 'utf8', (err) => {
            if (err) {
                reject(err);
            }
            console.log(`JSON guardado en: ${outputFilePath}`);
            resolve();
        });
    });
}

// Función para hacer POST con el JSON
function postJsonToEndpoint(jsonData, path) {
    return new Promise((resolve, reject) => {
        const data = JSON.stringify(jsonData);

        const options = {
            hostname: process.env.URL_ELASTIC,  // Solo el hostname, sin "https://"
            port: 9200,  // Puerto 443 para HTTPS
            path: path,  // La ruta de tu endpoint
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(data),
                "Authorization": "Basic " + process.env.AUTH_ELASTIC,
            }
        };

        const req = https.request(options, (res) => {
            let responseBody = '';

            res.on('data', (chunk) => {
                responseBody += chunk;
            });

            res.on('end', () => {
                resolve(JSON.parse(responseBody));
            });
        });

        req.on('error', (e) => {
            reject(e);
        });

        req.write(data);
        req.end();
    });
}

// Uso de las funciones
async function main() {
    try {
        const jsonData = await convertXMLToJson(args[3]);  // Reemplaza con la ruta de tu archivo XML

        // Guardar JSON en un archivo
        //await saveJsonToFile(jsonData, 'resultado.json');  // Especifica la ruta donde quieres guardar el archivo JSON
        // Enviar el JSON mediante POST
        for (var alertitem of jsonData.OWASPZAPReport.site.alerts.alertitem) {
            //alertitem.alert
            for (var instance of alertitem.instances.instance) {
                var data = {
                    alert: alertitem.alert,
                    riskcode: alertitem.riskcode,
                    confidence: alertitem.confidence,
                    riskdesc: alertitem.riskdesc,
                    confidencedesc: alertitem.confidencedesc,
                    desc: alertitem.desc,
                    uri: instance.uri,
                    method: instance.method,
                    param: instance.param,
                    attack: instance.attack,
                    evidence: instance.evidence,
                    otherinfo: instance.otherinfo,
                    project: args[0],
                    repository: args[1],
                    branch: args[2]
                }
                await postJsonToEndpoint(data, "/owasp/doc/" + args[0] + "-" + args[1] + "-" + args[2] + "-" + Buffer.from(data.alert + data.uri + data.method).toString('base64'));
            }
        }
    } catch (error) {
        console.error('Error:', error);
    }
}

main();
