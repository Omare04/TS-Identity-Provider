import mysql, { Pool, PoolConnection } from "mysql2/promise";
import jwt from "jsonwebtoken";
import { dbPool } from "./db";
import crypto from "crypto";


export interface User {
    password: string;
    id: number;
    fname: string;
    lname: string;
    email: string;
    position: string;
}

export function genAccessToken(user: User): string {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET!, { expiresIn: "5m" });
}

export function genRefreshToken(user: User): string {
    return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET!, { expiresIn: "1d" });
}

export async function setRefreshToken(
    token: string,
    user: User,
    tokenId: string
): Promise<void> {
    try {
        const connection: PoolConnection = await dbPool.getConnection();
        await connection.execute(
            "INSERT INTO refresh_tokens (user_id, token, token_id) VALUES (?, ?, ?)",
            [user.id, token, tokenId]
        );
        connection.release();
    } catch (err) {
        throw err;
    }
}

export async function getRefreshToken(tokenId: string): Promise<string | null> {
    try {
        const connection: PoolConnection = await dbPool.getConnection();
        const [rows] = await connection.execute(
            "SELECT token FROM refresh_tokens WHERE token_id = ?",
            [tokenId]
        );
        connection.release();
        return rows.length ? (rows[0].token as string) : null;
    } catch (err) {
        throw err;
    }
}

export async function generateRandomString(length: number): Promise<string> {
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
