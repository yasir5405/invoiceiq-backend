import mongoose from "mongoose";

const Schema = mongoose.Schema;

const ObjectId = Schema.ObjectId;

const refreshTokenSchema = new Schema(
  {
    token: { type: String, required: true, unique: true },
    userId: { type: ObjectId, ref: "users", required: true },
    expiresAt: { type: Date, required: true },
    isRevoked: { type: Boolean, default: false },
  },
  { timestamps: true }
);

const refreshTokenModel = mongoose.model("refresh-token", refreshTokenSchema);

export { refreshTokenModel };
