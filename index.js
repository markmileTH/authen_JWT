const express = require("express")
const jwt = require("jsonwebtoken")
require("dotenv").config()
const axios = require('axios');
const app = express()
const cors = require('cors'); // Import the cors package
app.use(express.json())
app.use(cors()); // Enable CORS for all routes
const port = process.env.PORT || 3000

const AD_SERVER = "https://ccf1-202-28-70-71.ngrok-free.app/authenticate"; 
const jwtValidate = (req, res, next) => {
    try {
        if (!req.headers["authorization"]) return res.sendStatus(401)

        const token = req.headers["authorization"].replace("Bearer ", "")

        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
            if (err) return res.sendStatus(403);
        })
        next()
    } catch (error) {
        return res.sendStatus(403)
    }
}



const jwtRefreshTokenValidate = (req, res, next) => {
    if (!req.headers["authorization"]) return res.sendStatus(401);
    
    const token = req.headers["authorization"].replace("Bearer ", "");
   
    jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, decoded) => {
        if (err) return res.sendStatus(403);

        req.user = decoded; // Assign the decoded token to req.user
        next(); // Move next() call inside the callback
    });
} 
 

app.get("/validate", jwtValidate, (req, res) => {
    res.send("Hello World!")
})

app.post("/auth/refresh", jwtRefreshTokenValidate, (req, res) => {
    const access_token = jwt.sign(
        { username: req.user.username, userID: req.user.userID },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "3m", algorithm: "HS256" }
    );

    const refresh_token = jwt.sign(
        { username: req.user.username, userID: req.user.userID },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: "1d", algorithm: "HS256" }
    );
    
    return res.json({
        access_token,
        refresh_token,
    });
});



app.post("/auth/login", async (req, res) => {
    const { username, password } = req.body;

    // const userIndex = users.findIndex((e) => e.username === username);

    // if (userIndex < 0) return res.status(400).send('User not found'); // Use .status(400).send() instead of sendStatus(400).send()

    try {
        const response = await axios.post(AD_SERVER, { username, password });

        if (response.data.success) {
            // const access_token = jwtGenerate(users[userIndex]);
            // const refresh_token = jwtRefreshTokenGenerate(users[userIndex]);
            const userID = response.data.userID;
            const access_token = jwt.sign(
                { username: username, userID: userID },
                process.env.ACCESS_TOKEN_SECRET,
                { expiresIn: "1m", algorithm: "HS256" }
            )
            
            const refresh_token = jwt.sign(
                { username: username, userID: userID },
                process.env.REFRESH_TOKEN_SECRET,
                { expiresIn: "1d", algorithm: "HS256" }
            )

            // users[userIndex].refresh = refresh_token;

            res.json({
                access_token,
                refresh_token,
            });
        } else {
            return res.status(401).send('Authentication failed');
        }
    } catch (error) {
        console.error(error);
        return res.status(500).send("Error processing request"); // Ensure you return here
    }
});

// const jwtGenerate = (user) => {
    
//     const accessToken = jwt.sign(
//         { name: user.username, id: user.userID },
//         process.env.ACCESS_TOKEN_SECRET,
//         { expiresIn: "3m", algorithm: "HS256" }
//     )

//     return accessToken
// }

// const jwtRefreshTokenGenerate = (user) => {
//     const refreshToken = jwt.sign(
//         { name: user.username, id: user.userID },
//         process.env.REFRESH_TOKEN_SECRET,
//         { expiresIn: "1d", algorithm: "HS256" }
//     )

//     return refreshToken
// }
app.listen(port, () => {
    console.log(`app listening on port ${port}`)
})
