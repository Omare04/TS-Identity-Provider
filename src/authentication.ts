import express, { Request, Response } from "express";
import { User, getRefreshToken, setRefreshToken, genAccessToken, genRefreshToken, generateRandomString } from "./helper";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { dbPool } from "./db";

const Authenticationrouter = express();


Authenticationrouter.post("/login", async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;
        const query: string = "SELECT * FROM users WHERE email = ?";
        const [rows] = await dbPool.query(query, [email]);
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

Authenticationrouter.get("/logout", async (req: Request, res: Response) => {
    try {
        const tokenId: string = req.cookies.tokenId;
        const query: string = "DELETE FROM refresh_tokens WHERE token_id = ?";
        await dbPool.query(query, [tokenId]);
        res.clearCookie("accessToken");
        res.clearCookie("tokenId");
        res.status(204).send();
    } catch (error) {
        console.error("Error occurred during logout:", error);
        res.status(500).send("Internal Server Error");
    }
});


Authenticationrouter.get("/token", async (req: Request, res: Response) => {
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