const fs = require('fs').promises;
const path = require('path');
const https = require('https');
const http = require('http');
const { timeStamp } = require('console');
const args = process.argv.slice(2);

function wait(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function putRequest(path, data) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: process.env.URL_ELASTIC,
            path: path,
            method: 'PUT',
            port: 80,
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(data),
                "Authorization": "Basic " + process.env.AUTH_ELASTIC,
            }
        };

        const req = http.request(options, (res) => {
            let responseData = '';
            res.on('data', (chunk) => { responseData += chunk; });
            res.on('end', () => { resolve(responseData); });
        });

        req.on('error', (e) => { reject(e); });
        req.write(data);
        req.end();
    });
}

function postRequest(path, data) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: process.env.URL_ELASTIC,
            path: path,
            method: 'POST',
            port: 80,
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(data),
                "Authorization": "Basic " + process.env.AUTH_ELASTIC,
            }
        };

        const req = http.request(options, (res) => {
            let responseData = '';
            res.on('data', (chunk) => { responseData += chunk; });
            res.on('end', () => { resolve(responseData); });
        });

        req.on('error', (e) => { reject(e); });
        req.write(data);
        req.end();
    });
}

async function fetchCveData(cveId) {
    const options = {
        hostname: 'services.nvd.nist.gov',
        path: `/rest/json/cves/2.0?cveId=${cveId}`,
        method: 'GET',
        headers: {
            'apiKey': args[2] // Incluye la API Key en los encabezados
        }
    };

    return new Promise((resolve, reject) => {
        const req = https.request(options, (res) => {
            let data = '';

            res.on('data', (chunk) => {
                data += chunk;
            });

            res.on('end', () => {
                try {
                    const jsonData = JSON.parse(data);
                    resolve(jsonData);
                } catch (error) {
                    reject(`Error parsing JSON: ${error.message}`);
                }
            });
        });

        req.setTimeout(15000, () => {
            req.destroy();
            reject(new Error('NVD API request timeout'));
        });

        req.on('error', (error) => {
            reject(`Request error: ${error.message}`);
        });

        req.end();
    });
}

var i = 0;
// Función para leer el archivo JSON
async function readJsonFile(filePath) {
    try {
        const data = await fs.readFile(filePath, 'utf-8');
        var nvd
        var datajson = JSON.parse(data)
        const url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=';
        const totalResults = datajson.Results.reduce((acc, r) => acc + (r.Vulnerabilities ? r.Vulnerabilities.length : 0), 0);
        console.log(`[INFO] Iniciando procesamiento: ${datajson.Results.length} target(s), ${totalResults} vulnerabilidad(es) en total`);
        const uniqueDocIds = new Set();
        for (var result of datajson.Results) {
            console.log(`[TARGET] ${result.Target || '(sin target)'} | Type: ${result.Type || '-'}`);
            try {
                for (var vul of result.Vulnerabilities) {
                    vul.Red = false
                    try {
                        if (typeof vul.ExploitScore === 'number') {
                            console.log(`  [SKIP NVD] ${vul.VulnerabilityID} | ExploitScore ya en JSON: ${vul.ExploitScore}`)
                        } else {
                            console.log(`  [NVD] Consultando ${vul.VulnerabilityID}...`)
                            try {
                                nvd = await fetchCveData(vul.VulnerabilityID);

                                await wait(100);
                                var metric = nvd.vulnerabilities[0].cve.metrics
                                if (metric.hasOwnProperty('cvssMetricV31')) {
                                    vul.ExploitScore = metric.cvssMetricV31[0].exploitabilityScore
                                    console.log(`  [NVD OK] ${vul.VulnerabilityID} | ExploitScore (V31): ${vul.ExploitScore}`)
                                } else if (metric.hasOwnProperty('cvssMetricV30')) {
                                    vul.ExploitScore = metric.cvssMetricV30[0].exploitabilityScore
                                    console.log(`  [NVD OK] ${vul.VulnerabilityID} | ExploitScore (V30): ${vul.ExploitScore}`)
                                } else if (metric.hasOwnProperty('cvssMetricV2')) {
                                    vul.ExploitScore = metric.cvssMetricV2[0].exploitabilityScore
                                    console.log(`  [NVD OK] ${vul.VulnerabilityID} | ExploitScore (V2): ${vul.ExploitScore}`)
                                } else {
                                    vul.ExploitScore = "not found"
                                    console.log(`  [NVD] ${vul.VulnerabilityID} | Sin metricas de explotabilidad en NVD`)
                                }
                            } catch (error) {
                                vul.ExploitScore = "not found"
                                console.log(`  [NVD ERROR] ${vul.VulnerabilityID} | ${error.message || error}`)
                            }
                        }
                        if (vul.ExploitScore === "not found" && vul.CVSS && Object.keys(vul.CVSS).length > 0) {
                            const scores = Object.values(vul.CVSS)
                                .map(s => s.V3Score)
                                .filter(s => typeof s === 'number');
                            if (scores.length > 0) {
                                vul.ExploitScore = Math.max(...scores);
                                console.log(`  [CVSS FALLBACK] ${vul.VulnerabilityID} | ExploitScore desde CVSS Trivy: ${vul.ExploitScore}`)
                            } else {
                                console.log(`  [SIN SCORE] ${vul.VulnerabilityID} | Sin ExploitScore en NVD ni CVSS, se indexara como null`)
                            }
                        }
                        if (vul.ExploitScore !== "not found" && vul.Severity !== "CRITICAL") {
                            if (vul.ExploitScore >= 7) {
                                vul.Red = true
                                console.log(`  [RED] ${vul.VulnerabilityID} | ExploitScore ${vul.ExploitScore} >= 7 -> marcado como critico`)
                            }
                        } else if (vul.Severity == "CRITICAL") {
                            vul.Red = true
                            console.log(`  [RED] ${vul.VulnerabilityID} | Severity CRITICAL -> marcado como critico`)
                        }

                        const datavul = JSON.stringify({
                            VulnerabilityID: vul.VulnerabilityID,
                            brake: vul.Red,
                            Type: result.Type,
                            Class: result.Class,
                            Target: result.Target,
                            ExploitScore: vul.ExploitScore === "not found" ? null : vul.ExploitScore,
                            PkgName: vul.PkgName,
                            InstalledVersion: vul.InstalledVersion,
                            FixedVersion: vul.FixedVersion,
                            Severity: vul.Severity,
                            Title: vul.Title,
                            Description: vul.Description,
                            Project: args[3],
                            Repository: args[4],
                            Branch: args[5],
                            TimeStamp: new Date(),
                            Scope: args[0]

                        })
                        if (args[5].includes("develop") || args[5].includes("release") || args[5].includes("master")) {
                            try {
                                const docId = args[3] + "-" + args[4] + "-" + vul.PkgName.replace(/\//g, "_") + "-" + vul.VulnerabilityID + "-" + args[0];
                                uniqueDocIds.add(docId);
                                await putRequest("/elastic/trivy"+args[5]+"/doc/" + docId, datavul);
                                console.log(`  [ELASTIC OK] ${vul.VulnerabilityID} indexado (doc: ${docId})`)
                            } catch (err) {
                                console.error(`  [ELASTIC ERROR] ${vul.VulnerabilityID} | ${err.message}`);
                            }
                        }

                    } catch (error) {
                        console.error(`  [ERROR] Procesando ${vul.VulnerabilityID}: ${error.message || error}`);
                    }
                    i++;
                }
            } catch (error) {

            }
        }
        console.log(`[INFO] Procesamiento finalizado: ${i} vulnerabilidad(es) procesadas | ${uniqueDocIds.size} documentos unicos indexados en Elastic`)
        return datajson;
    } catch (error) {
        console.error('Error al leer o parsear el archivo JSON:', error);
        throw error;
    }
}

function escapeHtml(str) {
    if (str == null) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// Función para convertir JSON a HTML
function convertJsonToHtml(jsonData) {
    let html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerabilities Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 5px; }
        table { width: 50%; border-collapse: collapse; margin-top: 20px; font-size: 10px}
        th, td { border: 5px solid #ddd; padding: 8px; }
        th { background-color: #00BF6F; }
        h1 { text-align: center; }
        h2 { text-align: center; }
        .error {color: #ffffff; background-color: #bf0000}
    </style>
</head>
<body>
    <h1>Vulnerabilities Report</h1>
    <h2>Total: ${i}</h2>
    <table>
        <thead>
            <tr>
                <th>Target</th>
                <th>Vulnerability ID</th>
                <th>Brake Pipeline</th>
                <th>Exploit Score</th>
                <th>Package Name</th>
                <th>Installed Version</th>
                <th>Fixed Versions</th>
                <th>Status</th>
                <th>Severity</th>
                <th>Title</th>
                <th>Description</th>
                <th>References</th>
            </tr>
        </thead>
        <tbody>`;
    for (var results of jsonData.Results) {
        if (!results.Vulnerabilities) continue;
        results.Vulnerabilities.forEach(vul => {
            try {
                if (vul.Red) {
                    html += `
                    <tr class="error">
                    `
                } else {
                    html += `
                    <tr>
                    `
                }

                html += `
                <td>${escapeHtml(results.Target)}</td>
                <td>${escapeHtml(vul.VulnerabilityID)}</td>
                <td>${vul.Red}</td>
                <td>${vul.ExploitScore}</td>
                <td>${escapeHtml(vul.PkgName)}</td>
                <td>${escapeHtml(vul.InstalledVersion)}</td>
                <td>${escapeHtml(vul.FixedVersion)}</td>
                <td>${escapeHtml(vul.Status)}</td>
                <td>${escapeHtml(vul.Severity)}</td>
                <td><a href="${escapeHtml(vul.PrimaryURL)}" target="_blank">${escapeHtml(vul.Title)}</a></td>
                <td>${escapeHtml(vul.Description)}</td>
                <td>
                    <ul>`;
                (vul.References || []).forEach(ref => {
                    html += `<li><a href="${escapeHtml(ref)}" target="_blank">${escapeHtml(ref)}</a></li>`;
                });

                html += `</ul>
                </td>
            </tr>`;
            } catch (error) {
                console.error(`Error generando HTML para ${vul.VulnerabilityID} (${vul.PkgID}): ${error.message}`);
            }
        });
    }
    html += `
        </tbody>
    </table>
</body>
</html>`;

    return html;
}

// Función para guardar el HTML en un archivo
async function saveHtmlFile(filePath, htmlContent, jsonFilePath, jsonData) {
    try {
        await fs.writeFile(filePath, htmlContent, 'utf-8');
        await fs.writeFile(jsonFilePath, JSON.stringify(jsonData), 'utf-8');
        console.log(`Archivo HTML guardado en ${filePath}`);
    } catch (error) {
        console.error('Error al guardar el archivo HTML:', error);
        throw error;
    }
}

// Función principal
async function main() {
    var throwexception = false
    console.log(`[ARGS] ${JSON.stringify(args)}`);
    if (!args[0] || !args[1] || !args[3] || !args[4] || !args[5] || !args[6]) {
        return;
    }
    if (args[5].includes("develop") || args[5].includes("release") || args[5].includes("master")) {
        var datadelete = JSON.stringify({

            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "Project.keyword": args[3]
                            }
                        },
                        {
                            "term": {
                                "Repository.keyword": args[4]
                            }
                        },
                        {
                            "term": {
                                "Class.keyword": args[6]
                            }
                        },
                        {
                            "term": {
                                "Branch.keyword": args[5]
                            }
                        },
                        {
                            "term": {
                                "Scope.keyword": args[0]
                            }
                        }
                        
                    ]
                }
            }

        })
        console.log(datadelete)
        try {
            const resDelete = await postRequest("/elastic/trivy"+args[5]+"/_delete_by_query", datadelete);
            console.log('Respuesta del servidor en borrado:', resDelete);
        } catch (err) {
            console.error(`Error en borrado: ${err.message}`);
        }
    }

    const jsonFilePath = path.join(__dirname, args[0] + "/" + args[1]); // Ruta del archivo JSON
    const htmlFilePath = path.join(__dirname, args[0] + '/vulnerabilities.html'); // Ruta del archivo HTML

    try {
        const jsonData = await readJsonFile(jsonFilePath);
        const htmlContent = convertJsonToHtml(jsonData);
        await saveHtmlFile(htmlFilePath, htmlContent, jsonFilePath, jsonData);
        if (args[0] == "ci") {
            for (var results of jsonData.Results) {
                try {
                    for (var vul of results.Vulnerabilities) {
                        if (vul.Red) {
                            throwexception = true
                            console.log(`##[error] ***** Pipeline fallido por la vulnerabilidad ${vul.VulnerabilityID} en el paquete ${vul.PkgName} *********`)
                        }
                    }
                } catch (error) {
                    console.error(error);
                }
            }
        }
    } catch (error) {
        console.error('Error en el proceso:', error);
    }
    if (args[0] == "ci" && throwexception) {
        throw new Error('##[error] ERROR: Pipeline fallido por vulnerabilidades criticas encontradas y exploit score mayor de 7, por favor revisar informe trivy en pestaña, dependencias impactadas marcadas en rojo');
    }
}

// Ejecutar la función principal
main();
