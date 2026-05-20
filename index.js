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
                return reject(err);
            }
            xml2js.parseString(xmlData, { explicitArray: false }, (err, result) => {
                if (err) {
                    return reject(err);
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
                return reject(err);
            }
            console.log(`JSON guardado en: ${outputFilePath}`);
            resolve();
        });
    });
}

// Función para hacer POST con el JSON
function postJsonToEndpoint(jsonData, path, method) {
    return new Promise((resolve, reject) => {
        const data = JSON.stringify(jsonData);

        const options = {
            hostname: process.env.URL_ELASTIC, 
            port: 80, 
            path: path,  
            method: method,
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
                try {
                    resolve(JSON.parse(responseBody));
                } catch (e) {
                    resolve(responseBody);
                }
            });
        });

        req.setTimeout(15000, () => {
            req.destroy();
            reject(new Error('Elastic request timeout'));
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
        console.log(`[INFO] Leyendo XML: ${args[3]}`)
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

        console.log(`[INFO] Eliminando documentos previos en Elastic para project=${args[0]} repo=${args[1]} branch=${args[2]}`)
        console.log(datadelete)

        const deleteResult = await postJsonToEndpoint(datadelete, "/elastic/owasp/_delete_by_query","POST");
        console.log(`[INFO] Documentos eliminados: ${deleteResult.deleted ?? JSON.stringify(deleteResult)}`)

        // Guardar JSON en un archivo
        //await saveJsonToFile(jsonData, 'resultado.json');  // Especifica la ruta donde quieres guardar el archivo JSON
        // Enviar el JSON mediante POST
        var cont = 0;
        const alertitems = jsonData.OWASPZAPReport.site.alerts.alertitem;
        const alertitemArray = Array.isArray(alertitems) ? alertitems : [alertitems];
        console.log(`[INFO] Alertas encontradas: ${alertitemArray.length}`);
        for (var alertitem of alertitemArray) {
            var data = null;
            if (Array.isArray(alertitem.instances.instance)) {
                console.log(`  [ALERTA] "${alertitem.alert}" | riesgo: ${alertitem.riskdesc} | instancias: ${alertitem.instances.instance.length}`);
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
                    try {
                        await postJsonToEndpoint(data, "/elastic/owasp/doc/" + generarCadenaAleatoria(16), "PUT");
                        console.log(`    [ELASTIC OK] instancia indexada: ${instance.uri}`);
                    } catch (err) {
                        console.error(`    [ELASTIC ERROR] ${alertitem.alert} | ${instance.uri} | ${err.message}`);
                    }
                }
            }
            else {
                cont++
                console.log(`  [ALERTA] "${alertitem.alert}" | riesgo: ${alertitem.riskdesc} | instancias: 1`);
                data = {
                    alert: alertitem.alert,
                    riskcode: alertitem.riskcode,
                    confidence: alertitem.confidence,
                    riskdesc: alertitem.riskdesc,
                    confidencedesc: alertitem.confidencedesc,
                    solution: alertitem.solution,
                    alertotherinfo: alertitem.otherinfo,
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
                try {
                    await postJsonToEndpoint(data, "/elastic/owasp/doc/" + generarCadenaAleatoria(16), "PUT");
                    console.log(`    [ELASTIC OK] instancia indexada: ${alertitem.instances.instance.uri}`);
                } catch (err) {
                    console.error(`    [ELASTIC ERROR] ${alertitem.alert} | ${alertitem.instances.instance.uri} | ${err.message}`);
                }
            }
        }
        console.log(`[INFO] Procesamiento finalizado: ${cont} instancia(s) indexadas de ${alertitemArray.length} alerta(s)`)
    } catch (error) {
        console.error('Error:', error);
    }
}

main();
