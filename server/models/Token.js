import { Schema, model } from 'mongoose';

const schema = new Schema({
    tokenId: String,
    userId: String
});

export default model('Token', schema)