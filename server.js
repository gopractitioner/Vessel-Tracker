const express = require('express');
const AWS = require('aws-sdk');
const bodyParser = require('body-parser');
const { DynamoDBClient, PutItemCommand } = require("@aws-sdk/client-dynamodb");
const { DynamoDBDocumentClient, QueryCommand, ScanCommand } = require('@aws-sdk/lib-dynamodb');
const session = require('express-session');
const path = require('path');
const WebSocket = require('ws');
const https = require('https');
const http = require('http');
const fs = require('fs');
const mysql = require('mysql2');// use mysql2 instead of mysql
const { getSecret } = require('./secret.js');

const app = express();

// Read your SSL certificate and private key
const privateKey = fs.readFileSync('/path/to/private-key.pem', 'utf8');
const certificate = fs.readFileSync('/path/to/certificate.pem', 'utf8');
const ca = fs.readFileSync('/path/to/ca.pem', 'utf8');

const credentials = {
    key: privateKey,
    cert: certificate,
    ca: ca
};

// Create HTTP server
const httpServer = http.createServer(app);

// Create HTTPS server
const httpsServer = https.createServer(credentials, app);

const wss = new WebSocket.Server({ server: httpsServer }); // WebSocket on HTTPS only

let dbClient;
let docClient;

async function initializeDbClients() {
    try {
        const secret = await getSecret();
        dbClient = new DynamoDBClient({
            region: 'us-east-1',
            credentials: {
                accessKeyId: secret.accessKeyId,
                secretAccessKey: secret.secretAccessKey
            }
        });
        docClient = DynamoDBDocumentClient.from(dbClient);
        console.log("DynamoDB clients initialized successfully");
    } catch (error) {
        console.error("Failed to initialize DynamoDB clients:", error);
        process.exit(1); // Exit the program if the client can't be initialised
    }
}

// Configure AWS Cognito parameters
const cognito = new AWS.CognitoIdentityServiceProvider({
    region: 'us-east-1' // Set to the region of your Cognito User Pool
});

app.use(bodyParser.json());

// Configure session middleware
app.use(session({
    secret: 'your-secret-key', // Secret key for encrypting the session
    resave: false, // Do not save session if unchanged
    saveUninitialized: true, // Set up session for all requests, even if not initialized
    cookie: { secure: false } // Set to false in development, should be true in production when using HTTPS
}));

const USER_POOL_ID = 'us-east-1_KWQe9X3Pp'; // Replace with your User Pool ID
const CLIENT_ID = '3jgvd3uni2chn30us56m4fleem'; // Replace with your Client ID

app.use(express.static('public'));

// Register new user
app.post('/register', (req, res) => {
    const { email, password, givenName, familyName } = req.body;

    const params = {
        ClientId: CLIENT_ID,
        Username: email,
        Password: password,
        UserAttributes: [
            {
                Name: 'email',
                Value: email
            },
            {
                Name: 'given_name',
                Value: givenName
            },
            {
                Name: 'family_name',
                Value: familyName
            }
        ]
    };

    cognito.signUp(params, (err, data) => {
        if (err) {
            console.error('Error registering user:', err);
            return res.status(400).send(err.message || JSON.stringify(err));
        }
        res.json({
            message: 'User registered successfully!',
            data: data
        });
    });
});

// Confirm user registration
app.post('/confirm', (req, res) => {
    const { email, code } = req.body;

    const params = {
        ClientId: CLIENT_ID,
        Username: email, // Use email as username
        ConfirmationCode: code
    };

    cognito.confirmSignUp(params, (err, data) => {
        if (err) {
            console.error('Error confirming user:', err);
            return res.status(400).send(err.message || JSON.stringify(err));
        }
        res.json({
            message: 'User confirmed successfully!',
            data: data
        });
    });
});

// Login
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    const params = {
        AuthFlow: 'USER_PASSWORD_AUTH',
        ClientId: CLIENT_ID,
        AuthParameters: {
            USERNAME: email, // Use email as username
            PASSWORD: password
        }
    };

    cognito.initiateAuth(params, (err, data) => {
        if (err) {
            console.error('Error logging in:', err);
            return res.status(400).send(err.message || JSON.stringify(err));
        }

        req.session.user = {
            email: email,
            token: data.AuthenticationResult.AccessToken // You can save more information based on your needs
        };

        res.json({ redirectUrl: '/ship' });
    });
});

// Routing handler: redirect to ship.html
app.get('/ship', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'ship.html'), (err) => {
        if (err) {
            console.error('Error sending file:', err);
            return res.status(500).send('Internal Server Error');
        }
    });
});

// Route to check session
app.get('/check-session', (req, res) => {
    if (req.session.user) {
        res.status(200).send('Session exists');
    } else {
        res.status(401).send('No session');
    }
});

// Use Map to store ship data, with MMSI as the key
const allShips = new Map();

// Configure MySQL connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '527group10',
    database: 'map'
});

db.connect(err => {
    if (err) {
        console.error('Error connecting to MySQL:', err.stack);
        return;
    }
    console.log('Connected to MySQL as id ' + db.threadId);

    const createTableQuery = `
        CREATE TABLE IF NOT EXISTS ship (
            MMSI BIGINT PRIMARY KEY,
            Latitude DOUBLE,
            Longitude DOUBLE,
            Cog DOUBLE,
            CommunicationState INT,
            NavigationalStatus INT,
            PositionAccuracy BOOLEAN,
            Raim BOOLEAN,
            RateOfTurn DOUBLE,
            Sog DOUBLE,
            Timestamp INT,
            TrueHeading INT,
            ShipName VARCHAR(255),
            time_utc DATETIME
        )
    `;
    db.query(createTableQuery, (err, result) => {
        if (err) {
            console.error('Error creating ship table:', err.stack);
        } else {
            console.log('Ship table is ready.');
        }
    });
});

// Search for ships by MMSI
app.get('/search', (req, res) => {
    if (!req.session.user || !req.session.user.email) {
        return res.status(403).json({ error: 'Unauthorized access' });
    }

    const mmsi = req.query.mmsi;

    if (!mmsi) {
        return res.status(400).send({ error: 'MMSI is required' });
    }

    const userEmail = req.session.user.email;

    const item = {
        TableName: "UserSearches",
        Item: {
            "Email": { S: userEmail },
            "MMSI": { S: mmsi },
            "SearchTime": { S: new Date().toISOString() }
        }
    };

    try {
        dbClient.send(new PutItemCommand(item));
        console.log("Search stored successfully in DynamoDB.");
    } catch (error) {
        console.error("Error storing search in DynamoDB:", error);
        return res.status(500).send({ error: 'Failed to store search data' });
    }

    const query = `
        SELECT MMSI, Latitude, Longitude, Cog, CommunicationState, NavigationalStatus,
               PositionAccuracy, Raim, RateOfTurn, Sog, Timestamp, TrueHeading, ShipName, time_utc
        FROM ship
        WHERE MMSI = ?
        LIMIT 1
    `;

    db.query(query, [mmsi], (err, results) => {
        if (err) {
            console.error('Error searching ship from database:', err.stack);
            return res.status(500).send({ error: 'Database query failed' });
        }

        if (results.length > 0) {
            res.send(results[0]);
        } else {
            res.status(404).send({ error: 'Ship not found' });
        }
    });
});

// Other routes like /searchByName, /searchHistory, etc., will remain unchanged

// Search for ships by ShipName
app.get('/searchByName', (req, res) => {

    // Verify if the user is logged in
    if (!req.session.user || !req.session.user.email) {
        return res.status(403).json({ error: 'Unauthorized access' }); // Return 403 error if not logged in
    }

    const shipName = req.query.shipName;

    if (!shipName) {
        return res.status(400).send({ error: 'ShipName is required' });
    }

    const userEmail = req.session.user.email;
    //console.log("userId",userEmail)

    // Build a DynamoDB data item
    const item = {
        TableName: "UserSearches", // Your DynamoDB table name
        Item: {
            "Email": { S: userEmail },
            "shipName": { S: shipName },
            "SearchTime": { S: new Date().toISOString() } // Store search time
        }
    };

    try {
        // Store user search in DynamoDB
        dbClient.send(new PutItemCommand(item));
        console.log("Search stored successfully in DynamoDB.");
    } catch (error) {
        console.error("Error storing search in DynamoDB:", error);
        return res.status(500).send({ error: 'Failed to store search data' });
    }
    const query = `
        SELECT MMSI, Latitude, Longitude, Cog, CommunicationState, NavigationalStatus, 
               PositionAccuracy, Raim, RateOfTurn, Sog, Timestamp, TrueHeading, ShipName, time_utc
        FROM ship
        WHERE ShipName LIKE ?
        LIMIT 10
    `;

    db.query(query, [`%${shipName}%`], (err, results) => {
        if (err) {
            console.error('Error searching ship from database:', err.stack);
            return res.status(500).send({ error: 'Database query failed' });
        }

        if (results.length > 0) {
            res.send(results);
        } else {
            res.status(404).send({ error: 'No ships found' });
        }
    });
});

//docClient = DynamoDBDocumentClient.from(dbClient);
app.get('/searchHistory', async (req, res) => {
    if (!req.session.user || !req.session.user.email) {
        return res.status(403).json({ error: 'Unauthorized access' });
    }
    // Check if the database client is initialized
    if (!docClient) {
        return res.status(503).json({ error: 'Database client not initialized' });
    }
    const userEmail = req.session.user.email;
    const params = {
        TableName: "UserSearches",
        FilterExpression: "Email = :email",
        ExpressionAttributeValues: {
            ":email": userEmail
        }
    };

    try {
        // Create and send ScanCommand
        const command = new ScanCommand(params);
        const { Items } = await docClient.send(command);
        res.json(Items || []);
    } catch (error) {
        console.error('Error querying DynamoDB:', error);
        res.status(500).send({ error: 'Failed to retrieve data' });
    }
});










// WebSocket logic also remains unchanged

// Create a buffer array to store pending ship data
const shipDataBuffer = [];

// Connect to aisstream.io WebSocket
const aisSocket = new WebSocket('wss://stream.aisstream.io/v0/stream');

aisSocket.on('open', function open() {
    console.log('Connected to aisstream.io');

    const subscriptionMessage = {
        Apikey: '431a0cfa3a12578db359c614a01d4551dbf77f9a',
        BoundingBoxes: [[[-90, -180], [90, 180]]],
        FilterMessageTypes: ["PositionReport"]
    };

    aisSocket.send(JSON.stringify(subscriptionMessage));
});

aisSocket.on('message', function incoming(data) {
    const aisMessage = JSON.parse(data);
    const mmsi = aisMessage.MetaData.MMSI;

    // Update or add ship data
    allShips.set(mmsi, aisMessage);

    const { PositionReport } = aisMessage.Message;
    const { MetaData } = aisMessage;
    const timeUtc = new Date(MetaData.time_utc).toISOString().slice(0, 19).replace('T', ' ');

    // Push the data into the buffer array
    shipDataBuffer.push([
        mmsi,
        MetaData.latitude,
        MetaData.longitude,
        PositionReport.Cog,
        PositionReport.CommunicationState,
        PositionReport.NavigationalStatus,
        PositionReport.PositionAccuracy,
        PositionReport.Raim,
        PositionReport.RateOfTurn,
        PositionReport.Sog,
        PositionReport.Timestamp,
        PositionReport.TrueHeading,
        MetaData.ShipName,
        timeUtc
    ]);

    // If the buffer array reaches batch size, perform an immediate database insert
    if (shipDataBuffer.length >= 1000) {
        console.log("Buffer full, performing batch insert.");

        const insertQuery = `
            INSERT INTO ship (MMSI, Latitude, Longitude, Cog, CommunicationState, NavigationalStatus, PositionAccuracy, Raim, RateOfTurn, Sog, Timestamp, TrueHeading, ShipName, time_utc)
            VALUES ?
            ON DUPLICATE KEY UPDATE
            Latitude = VALUES(Latitude),
            Longitude = VALUES(Longitude),
            Cog = VALUES(Cog),
            CommunicationState = VALUES(CommunicationState),
            NavigationalStatus = VALUES(NavigationalStatus),
            PositionAccuracy = VALUES(PositionAccuracy),
            Raim = VALUES(Raim),
            RateOfTurn = VALUES(RateOfTurn),
            Sog = VALUES(Sog),
            Timestamp = VALUES(Timestamp),
            TrueHeading = VALUES(TrueHeading),
            ShipName = VALUES(ShipName),
            time_utc = VALUES(time_utc)
        `;

        db.query(insertQuery, [shipDataBuffer], (err, result) => {
            if (err) {
                console.error('Error in batch insert:', err.stack);
            } else {
                console.log(`Batch insert successful, inserted/updated ${result.affectedRows} rows.`);
            }
        });

        // Clear the buffer array
        shipDataBuffer.length = 0;
    }
});

// Filter ship data, returning only ships within the specified bounds
function filterShipsByBounds(ships, bounds) {
    return ships.filter(ship => {
        const latitude = ship.MetaData.latitude;
        const longitude = ship.MetaData.longitude;
        return longitude >= bounds.west && longitude <= bounds.east &&
            latitude >= bounds.south && latitude <= bounds.north;
    });
}

// Handle WebSocket errors
aisSocket.on('error', function error(err) {
    console.error('WebSocket error:', err);
});

// Provide frontend static files
app.use(express.static('public'));

// Handle WebSocket connections from the browser
wss.on('connection', function connection(ws) {
    console.log('Browser connected to WebSocket server');

    ws.on('message', function incoming(message) {
        const bounds = JSON.parse(message);
        ws.bounds = bounds;

        // Construct a query statement, limiting the result to 50 records
        const query = `
            SELECT MMSI, Latitude, Longitude, Cog, CommunicationState, NavigationalStatus, 
                   PositionAccuracy, Raim, RateOfTurn, Sog, Timestamp, TrueHeading, ShipName, time_utc
            FROM ship
            WHERE Longitude BETWEEN ? AND ? AND Latitude BETWEEN ? AND ?
            ORDER BY time_utc DESC
            LIMIT 50
        `;

        // Execute the query
        db.query(query, [bounds.west, bounds.east, bounds.south, bounds.north], (err, results) => {
            if (err) {
                console.error('Error querying ships from database:', err.stack);
                ws.send(JSON.stringify({ error: 'Database query failed' }));
                return;
            }

            // Send the query results to the front end
            ws.send(JSON.stringify(results));
        });
    });

    ws.on('close', function () {
        console.log('Browser disconnected');
    });
});

// Stop sending data to the client when the map is dragged
function stopSendingData(ws) {
    ws.sendingData = false;
}



// Redirect HTTP to HTTPS
app.use((req, res, next) => {
    if (req.protocol === 'http') {
        res.redirect(`https://${req.headers.host}${req.url}`);
    } else {
        next();
    }
});

// Start both HTTP and HTTPS servers
const HTTP_PORT = 80;
const HTTPS_PORT = 443;

async function startServer() {
    await initializeDbClients();

    httpServer.listen(HTTP_PORT, () => {
        console.log(`HTTP server is listening on port ${HTTP_PORT}`);
    });

    httpsServer.listen(HTTPS_PORT, () => {
        console.log(`HTTPS server is listening on port ${HTTPS_PORT}`);
    });
}

startServer().catch(error => {
    console.error("Failed to start server:", error);
    process.exit(1);
});
