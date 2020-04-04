import jwt from 'jsonwebtoken';
import config from '../config';

export default (req, res, next) => {
    const token = req.headers['x-access-token'];

    if (!token) {
        return res.status(401).json({ msg: 'No access token' });
    }

    try {
        const payload = jwt.verify(token, config.jwt.secret);

        if (payload.type !== 'access') {
            return res.status(403).json({ msg: 'Invalid token' });
        }
    } catch (e) {
        if (e instanceof jwt.TokenExpiredError) {
            return res.status(403).json({ msg: 'Token expired' });
        }

        if (e instanceof jwt.JsonWebTokenError) {
            return res.status(403).json({ msg: 'Invalid token' });
        }
    }

    next();
};