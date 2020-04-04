import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import Token from '../models/Token';
import config from '../config';

const generateAccessToken = userId => {
    const payload = {
        userId,
        type: config.jwt.tokens.access.type
    };
    const options = {
        expiresIn: config.jwt.tokens.access.expiresIn
    };

    return jwt.sign(
        payload,
        config.jwt.secret,
        options
    );
}

const generateRefreshToken = () => {
    const payload = {
        tokenId: uuidv4(),
        type: config.jwt.tokens.refresh.type
    };
    const options = {
        expiresIn: config.jwt.tokens.refresh.expiresIn
    }

    return {
        tokenId: payload.tokenId,
        token: jwt.sign(
            payload,
            config.jwt.secret,
            options
        )
    };
}

const replaceDbRefreshToken = async (tokenId, userId) => {
    try {
        await Token.findOneAndRemove({ userId });
        const token = new Token({ tokenId, userId });
        await token.save();

        return token;
    } catch (e) {
        throw e;
    }
}

export const updateTokens = async userId => {
    try {
        const accessToken = generateAccessToken(userId);
        const refreshToken = generateRefreshToken();

        await replaceDbRefreshToken(refreshToken.tokenId, userId);

        return ({
            accessToken,
            refreshToken: refreshToken.token
        })
    } catch (e) {
        throw e;
    }
}
