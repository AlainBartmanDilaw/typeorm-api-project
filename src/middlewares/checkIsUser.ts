import { NextFunction, Request, Response } from 'express';

export const checkIsUser = (req: Request, res: Response, next: NextFunction) => {
  const currentUserId = res.locals.jwtPayload.userId;
  if (currentUserId === Number(req.params.id)) {
    next();
  } else {
    console.log('checkIsUser');
    res.status(401).send();
    return;
  }
};
