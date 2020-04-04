import "@babel/polyfill";
import express from 'express';
import mongoose from 'mongoose';
import authRoute from './routes/auth.routes';
import config from './config';
import authMiddleware from './middleware/auth';

const PORT = config.port;

const app = express();

app.use(express.json());
app.use('/api/auth', authRoute)
app.get('/products', authMiddleware, (req, res) => {
    res.json({ products: [1,2,3,4,5]});
})

async function start() {
    try {
        await mongoose.connect(config.mongoURI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            useCreateIndex: true
        });

        app.listen(PORT, () => console.log(`server is listening on port ${PORT}`));
    } catch (e) {
        console.log(`Server error ${e.message}`);
        process.exit(1);
    }
}

start();
