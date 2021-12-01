import cors from "cors";
import express, { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import decode from "jwt-decode";
import { generateJwtAndRefreshToken } from "./auth";
import { auth } from "./config";

import {
  checkRefreshTokenIsValid,
  users,
  seedUserStore,
  invalidateRefreshToken,
} from "./database";
import { CreateSessionDTO, DecodedToken } from "./types";

const app = express();

app.use(express.json());
app.use(cors());

seedUserStore();

function checkAuthMiddleware(
  request: Request,
  response: Response,
  next: NextFunction
) {
  const { authorization } = request.headers;

  if (!authorization) {
    return response.status(401).json({
      error: true,
      code: "token.invalid",
      message: "Token não está presente.",
    });
  }

  const [, token] = authorization?.split(" ");

  if (!token) {
    return response.status(401).json({
      error: true,
      code: "token.invalid",
      message: "Token não está presente.",
    });
  }

  try {
    const decoded = jwt.verify(token as string, auth.secret) as DecodedToken;

    request.user = decoded.sub;

    return next();
  } catch (err) {
    return response
      .status(401)
      .json({ error: true, code: "token.expired", message: "Token inválido." });
  }
}

function addUserInformationToRequest(
  request: Request,
  response: Response,
  next: NextFunction
) {
  const { authorization } = request.headers;

  if (!authorization) {
    return response.status(401).json({
      error: true,
      code: "token.invalid",
      message: "Token não está presente.",
    });
  }

  const [, token] = authorization?.split(" ");

  if (!token) {
    return response.status(401).json({
      error: true,
      code: "token.invalid",
      message: "Token não está presente.",
    });
  }

  try {
    const decoded = decode(token as string) as DecodedToken;

    request.user = decoded.sub;

    return next();
  } catch (err) {
    return response.status(401).json({
      error: true,
      code: "token.invalid",
      message: "Formato do token inválido.",
    });
  }
}

app.post("/sessions", (request, response) => {
  const { email, password } = request.body as CreateSessionDTO;

  const user = users.get(email);

  if (!user || password !== user.password) {
    return response.status(401).json({
      error: true,
      message: "E-mail ou senha incorreta.",
    });
  }

  const { token, refreshToken } = generateJwtAndRefreshToken(email, {
    permissions: user.permissions,
    roles: user.roles,
  });

  return response.json({
    message: "Usuário autentificado.",
    token,
    refreshToken,
    permissions: user.permissions,
    roles: user.roles,
  });
});

app.post("/refresh", addUserInformationToRequest, (request, response) => {
  const email = request.user;
  const { refreshToken } = request.body;

  const user = users.get(email);

  if (!user) {
    return response.status(401).json({
      error: true,
      message: "Usuário não encontrado.",
    });
  }

  if (!refreshToken) {
    return response
      .status(401)
      .json({ error: true, message: "Refresh token é obrigatório." });
  }

  const isValidRefreshToken = checkRefreshTokenIsValid(email, refreshToken);

  if (!isValidRefreshToken) {
    return response
      .status(401)
      .json({ error: true, message: "Refresh token é inválido." });
  }

  invalidateRefreshToken(email, refreshToken);

  const { token, refreshToken: newRefreshToken } = generateJwtAndRefreshToken(
    email,
    {
      permissions: user.permissions,
      roles: user.roles,
    }
  );

  return response.json({
    token,
    refreshToken: newRefreshToken,
    permissions: user.permissions,
    roles: user.roles,
  });
});

app.get("/me", checkAuthMiddleware, (request, response) => {
  const email = request.user;

  const user = users.get(email);

  if (!user) {
    return response
      .status(400)
      .json({ error: true, message: "Usuário não encontrado." });
  }

  return response.json({
    email,
    permissions: user.permissions,
    roles: user.roles,
  });
});

app.listen(3333);
