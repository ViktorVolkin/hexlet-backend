/*
  Warnings:

  - You are about to drop the column `hashedRefreshToken` on the `User` table. All the data in the column will be lost.

*/
-- DropIndex
DROP INDEX "User_hashedRefreshToken_key";

-- DropIndex
DROP INDEX "User_username_key";

-- AlterTable
ALTER TABLE "User" DROP COLUMN "hashedRefreshToken";

-- CreateTable
CREATE TABLE "HashedTokens" (
    "id" SERIAL NOT NULL,
    "userId" INTEGER NOT NULL,
    "token" TEXT NOT NULL,

    CONSTRAINT "HashedTokens_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "HashedTokens_token_key" ON "HashedTokens"("token");

-- AddForeignKey
ALTER TABLE "HashedTokens" ADD CONSTRAINT "HashedTokens_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
