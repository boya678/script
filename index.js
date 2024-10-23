const fs = require('fs');
const xml2js = require('xml2js');
const http = require('http');
const args = process.argv.slice(2);
const crypto = require('crypto');

// Función para generar una cadena aleatoria de longitud específica
function generarCadenaAleatoria(longitud) {
    return crypto.randomBytes(longitud)
        .toString('hex') // Convertir a hexadecimal
        .slice(0, longitud); // Asegurarse de que tenga la longitud deseada
}

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

        const req = http.request(options, (res) => {
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


        var datadelete = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "project.keyword": args[0]
                            }
                        },
                        {
                            "term": {
                                "repository.keyword": args[1]
                            }
                        },
                        {
                            "term": {
                                "branch.keyword": args[2]
                            }
                        }
                    ]
                }
            }
        }

        console.log(datadelete)

        console.log(await postJsonToEndpoint(datadelete, "/owasp/_delete_by_query"));

        // Guardar JSON en un archivo
        //await saveJsonToFile(jsonData, 'resultado.json');  // Especifica la ruta donde quieres guardar el archivo JSON
        // Enviar el JSON mediante POST
        var cont = 0;
        for (var alertitem of jsonData.OWASPZAPReport.site.alerts.alertitem) {
            var data = null;
            if (Array.isArray(alertitem.instances.instance)) {
                for (var instance of alertitem.instances.instance) {
                    cont++
                    data = {
                        alert: alertitem.alert,
                        riskcode: alertitem.riskcode,
                        confidence: alertitem.confidence,
                        riskdesc: alertitem.riskdesc,
                        solution: alertitem.solution,
                        alertotherinfo: alertitem.otherinfo,
                        confidencedesc: alertitem.confidencedesc,
                        reference: alertitem.reference,
                        desc: alertitem.desc,
                        uri: instance.uri,
                        method: instance.method,
                        param: instance.param,
                        attack: instance.attack,
                        evidence: instance.evidence,
                        instanceotherinfo: instance.otherinfo,
                        project: args[0],
                        repository: args[1],
                        branch: args[2],
                        timestamp: new Date()
                    }
                    await postJsonToEndpoint(data, "/owasp/doc/" + generarCadenaAleatoria(128));
                }
            }
            else {
                cont++
                data = {
                    alert: alertitem.alert,
                    riskcode: alertitem.riskcode,
                    confidence: alertitem.confidence,
                    riskdesc: alertitem.riskdesc,
                    confidencedesc: alertitem.confidencedesc,
                    solution: alertitem.solution,
                    alertotherinfo: alertitem.otherinfo,
                    confidencedesc: alertitem.confidencedesc,
                    reference: alertitem.reference,
                    desc: alertitem.desc,
                    uri: alertitem.instances.instance.uri,
                    method: alertitem.instances.instance.method,
                    param: alertitem.instances.instance.param,
                    attack: alertitem.instances.instance.attack,
                    evidence: alertitem.instances.instance.evidence,
                    instanceotherinfo: alertitem.instances.instance.otherinfo,
                    project: args[0],
                    repository: args[1],
                    branch: args[2],
                    timestamp: new Date()
                }
                await postJsonToEndpoint(data, "/owasp/doc/" + generarCadenaAleatoria(128));
            }
        }
        console.log(cont)
    } catch (error) {
        console.error('Error:', error);
    }
}

main();
