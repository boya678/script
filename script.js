const fs = require('fs').promises;
const path = require('path');
const https = require('https');

const args = process.argv.slice(2);

function wait(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
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
        var datajson = JSON.parse(data)
        const url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=';
        for (var result of datajson.Results) {
            try {
                for (var vul of result.Vulnerabilities) {
                    try {
                        const data = await fetchCveData(vul.VulnerabilityID);
                        await wait(0);
                        var metric = data.vulnerabilities[0].cve.metrics
                        if (metric.hasOwnProperty('cvssMetricV31')) {
                            vul.ExploitScore = metric.cvssMetricV31[0].exploitabilityScore
                        } else if (metric.hasOwnProperty('cvssMetricV30')) {
                            vul.ExploitScore = metric.cvssMetricV30[0].exploitabilityScore
                        } else if (metric.hasOwnProperty('cvssMetricV2')) {
                            vul.ExploitScore = metric.cvssMetricV2[0].exploitabilityScore
                        } else {
                            vul.ExploitScore = "not found"
                        }
                    } catch (error) {
                        console.error('Error al obtener los datos:', error.message);
                    }
                    i++;
                }
            } catch (error) {

            }
        }
        return datajson;
    } catch (error) {
        console.error('Error al leer o parsear el archivo JSON:', error);
        throw error;
    }
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
        try {
            results.Vulnerabilities.forEach(vul => {
                html += `
            <tr>
                <td>${results.Target}</td>
                <td>${vul.VulnerabilityID}</td>
                <td>${vul.ExploitScore}</td>
                <td>${vul.PkgName}</td>
                <td>${vul.InstalledVersion}</td>
                <td>${vul.FixedVersion}</td>
                <td>${vul.Status}</td>
                <td>${vul.Severity}</td>
                <td><a href="${vul.PrimaryURL}" target="_blank">${vul.Title}</a></td>
                <td>${vul.Description}</td>
                <td>
                    <ul>`;
                vul.References.forEach(ref => {
                    html += `<li><a href="${ref}" target="_blank">${ref}</a></li>`;
                });

                html += `</ul>
                </td>
            </tr>`;
            });
        } catch (error) {

        }
    }
    html += `
        </tbody>
    </table>
</body>
</html>`;

    return html;
}

// Función para guardar el HTML en un archivo
async function saveHtmlFile(filePath, htmlContent,jsonFilePath, jsonData ) {
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
    const jsonFilePath = path.join(__dirname, args[0]+"/"+args[1]); // Ruta del archivo JSON
    const htmlFilePath = path.join(__dirname, args[0]+'/vulnerabilities.html'); // Ruta del archivo HTML

    try {
        const jsonData = await readJsonFile(jsonFilePath);
        const htmlContent = convertJsonToHtml(jsonData);
        await saveHtmlFile(htmlFilePath, htmlContent,jsonFilePath, jsonData);
    } catch (error) {
        console.error('Error en el proceso:', error);
    }
}

// Ejecutar la función principal
main();
