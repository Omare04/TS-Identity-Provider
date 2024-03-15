import express, { Request, Response, NextFunction } from "express";
import mysql, { Pool, PoolConnection } from "mysql2/promise";
import bcrypt from "bcrypt";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import cors from "cors";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import axios from "axios";
import crypto from "crypto";

dotenv.config();

interface User {
  id: number;
  fname: string;
  lname: string;
  email: string;
  position: string;
}

const router = express();
router.use(bodyParser.urlencoded({ extended: true }));
router.use(cookieParser());
router.use(bodyParser.json());

const dbport = 3301;
const dbhost = "localhost";
const dbname = "Stock_AOM";
const dbuser = "root";
const dbpass = "";

const pool: Pool = mysql.createPool({
  host: dbhost,
  port: dbport,
  user: dbuser,
  database: dbname,
  password: dbpass,
});

router.use(
  cors({
    origin: "http://localhost:5173",
    methods: ["GET", "POST"],
    credentials: true,
  })
);

async function getUser(id: number): Promise<User[]> {
  try {
    const connection: PoolConnection = await pool.getConnection();
    const [rows] = await connection.execute("SELECT * FROM users WHERE id = ?", [
      id,
    ]);
    connection.release();
    return rows as User[];
  } catch (e) {
    throw e;
  }
}

function genAccessToken(user: User): string {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET!, { expiresIn: "5m" });
}

function genRefreshToken(user: User): string {
  return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET!, { expiresIn: "1d" });
}

async function setRefreshToken(
  token: string,
  user: User,
  tokenId: string
): Promise<void> {
  try {
    const connection: PoolConnection = await pool.getConnection();
    await connection.execute(
      "INSERT INTO refresh_tokens (user_id, token, token_id) VALUES (?, ?, ?)",
      [user.id, token, tokenId]
    );
    connection.release();
  } catch (err) {
    throw err;
  }
}

async function getRefreshToken(tokenId: string): Promise<string | null> {
  try {
    const connection: PoolConnection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT token FROM refresh_tokens WHERE token_id = ?",
      [tokenId]
    );
    connection.release();
    return rows.length ? rows[0].token : null;
  } catch (err) {
    throw err;
  }
}

async function generateRandomString(length: number): Promise<string> {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(length, (err, buffer) => {
      if (err) {
        reject(err);
      } else {
        resolve(buffer.toString("hex"));
      }
    });
  });
}

router.post("/register", async (req: Request, res: Response) => {
  try {
    const { fname, lname, email, password, position } = req.body;
    const salt: string = await bcrypt.genSalt();
    const hashedPassword: string = await bcrypt.hash(password, salt);
    const query: string =
      "INSERT INTO users (fname, lname, email, password, position) VALUES (?, ?, ?, ?, ?)";
    await pool.query(query, [fname, lname, email, hashedPassword, position]);
    res.sendStatus(200);
  } catch (error) {
    console.error("Error occurred during registration:", error);
    res.status(500).send("Internal Server Error");
  }
});

router.post("/login", async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    const query: string = "SELECT * FROM users WHERE email = ?";
    const [rows] = await pool.query(query, [email]);
    if (rows.length === 0) {
      res.status(404).send("User not found");
      return;
    }
    const user: User = rows[0] as User;
    const validPassword: boolean = await bcrypt.compare(
      password,
      user.password
    );
    if (!validPassword) {
      res.status(401).send("Invalid password");
      return;
    }
    const tokenId: string = await generateRandomString(16);
    const accessToken: string = genAccessToken(user);
    const refreshToken: string = genRefreshToken(user);
    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      sameSite: "strict",
    });
    res.cookie("tokenId", tokenId, { httpOnly: true, sameSite: "strict" });
    await setRefreshToken(refreshToken, user, tokenId);
    res.status(200).send({ message: "Login successful", user });
  } catch (error) {
    console.error("Error occurred during login:", error);
    res.status(500).send("Internal Server Error");
  }
});

router.get("/logout", async (req: Request, res: Response) => {
  try {
    const tokenId: string = req.cookies.tokenId;
    const query: string = "DELETE FROM refresh_tokens WHERE token_id = ?";
    await pool.query(query, [tokenId]);
    res.clearCookie("accessToken");
    res.clearCookie("tokenId");
    res.status(204).send();
  } catch (error) {
    console.error("Error occurred during logout:", error);
    res.status(500).send("Internal Server Error");
  }
});

router.get("/token", async (req: Request, res: Response) => {
  try {
    const tokenId: string = req.cookies.tokenId;
    if (!tokenId) {
      res.status(401).send("Unauthorized");
      return;
    }
    const refreshToken: string | null = await getRefreshToken(tokenId);
    if (!refreshToken) {
      res.clearCookie("accessToken");
      res.clearCookie("tokenId");
      res.status(401).send("Unauthorized");
      return;
    }
    const accessToken: string = req.cookies.accessToken;
    jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET!, (err, user) => {
      if (err) {
        const newAccessToken: string = genAccessToken(user as User);
        res.cookie("accessToken", newAccessToken, {
          httpOnly: true,
          sameSite: "strict",
        });
        res.status(200).send({ user });
      } else {
        res.status(200).send({ user });
      }
    });
  } catch (error) {
    console.error("Error occurred during token validation:", error);
    res.status(500).send("Internal Server Error");
  }
});

export default router;
