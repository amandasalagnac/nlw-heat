import { Request, Response, NextFunction } from 'express';
import { verify } from 'jsonwebtoken';

interface IPayload {
  sub: string;
}

export function ensureAuthenticated(
  request: Request,
  response: Response,
  next: NextFunction
) {
  const authToken = request.headers.authorization;

  if (!authToken) {
    return response.status(401).json({
      errorCode: 'token.invalid',
    });
  }

  // Quando recebemos um token dentro do headers, ele vem com a seguinte estrutura:
  // Bearer kuhf47iryoifh387yhifh239j23h
  // Para continuarmos, precisamos desestruturar
  // [0] -> Bearer
  // [1] -> kuhf47iryoifh387yhifh239j23h (o token)

  const [, token] = authToken.split(' ');

  try {
    const { sub } = verify(token, process.env.JWT_SECRET) as IPayload; // o sub é a id do usuário

    request.user_id = sub;
    return next();
  } catch {
    return response.status(401).json({ errorCode: 'token.expired' });
  }
}
