import express from "express";
import fetch from "node-fetch";
import keys from "./sources/keys.js";
const app = express();

app.use(express.json());

app.get("/", (req, res) => {
  res.send("hello from backend to frontend!");
});

app.get("/weather/:cityName", (req, res) => {
  const cityName = req.params.cityName;
  fetch(
    `https://api.openweathermap.org/data/2.5/weather?q=${cityName}&appid=${keys.API_KEY}`
  )
    .then((response) => response.json())
    .then((response) => {
      if (response.name === undefined) {
        res.status(404).json({ weatherText: "City not found!" });
      } else {
        return res.json({
          cityName: response.name,
          temperature: (response.main.temp - 273.15).toFixed(2),
        });
      }
    })
    .catch((error) => res.json({ weatherText: error.message }));
});

export default app;
