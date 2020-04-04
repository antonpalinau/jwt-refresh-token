import 'dotenv/config';

export default {
    port: process.env.PORT || 5000,
    mongoURI: process.env.MONGO_URI,
    jwt: {
        secret: process.env.SECRET,
        tokens: {
            access: {
                type: 'access',
                expiresIn: process.env.TOKEN_EXPIRES_IN
            },
            refresh: {
                type: 'refresh',
                expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN
            }
        }
    }
}
