import mongoose from "mongoose";

const { Schema } = mongoose;

const tokenSchema = new Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: "User",
    },
    accessToken: {
        type: String,
        required: true,
    },
    refreshToken: {
        type: String,
        required: true,
    },
    accessExpiresAt: {
        type: Date,
        required: true
    },
    refreshExpiresAt: {
        type: Date,
        required: true
    }
});

export default mongoose.model("Token", tokenSchema);
