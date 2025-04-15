-- AlterTable
ALTER TABLE "User" ALTER COLUMN "passwordResetToken" DROP NOT NULL,
ALTER COLUMN "passwordResetExpiry" DROP NOT NULL;
