import app from "../app.js";
import supertest from "supertest";

const request = supertest(app);

describe("POST /", () => {
  it("Should return a 200 status", async () => {
    const response = await request.get("/");
    expect(response.status).toBe(200);
  });
  it("Should return a 200 status with the correct data", async () => {
    const response = await request.get("/");
    expect(response.text).toBe("hello from backend to frontend!");
  });
});

describe("POST /weather/:cityName", () => {
  it("Should return a 200 status", async () => {
    const response = await request.post("/weather/London");
    expect(response.status).toBe(200);
  });

  it("Should return a 404 status", async () => {
    const response = await request.post("/weather/NotACity");
    expect(response.status).toBe(404);
  });

  it("Should return a 200 status with the correct data", async () => {
    const response = await request.post("/weather/London");
    expect(response.body.cityName).toBe("London");
    expect(response.body.temperature).toBeDefined();
  });

  it("Should return a 404 status with a wrong city name", async () => {
    const response = await request.post("/weather/unknown");
    expect(response.body.weatherText).toBe("City not found!");
  });
});
