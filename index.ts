import express, { Request, Response, NextFunction } from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import path from "path";
import fs from "fs";
import multer from "multer";
import { PrismaClient, User } from "@prisma/client";

const app = express();
const prisma = new PrismaClient();

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";

// Paths
const staticRoot = path.join(__dirname, "public");
const uploadsRoot = path.join(__dirname, "uploads");
const certDir = path.join(uploadsRoot, "certificates");

// Ensure uploads directories exist
fs.mkdirSync(certDir, { recursive: true });

// Multer storage for certificates (PDF/DOC/DOCX, 5MB)
const storage = multer.diskStorage({
  destination: (
    _req: Request,
    _file: Express.Multer.File,
    cb: (err: Error | null, dest: string) => void
  ) => {
    cb(null, certDir);
  },
  filename: (
    req: Request,
    file: Express.Multer.File,
    cb: (err: Error | null, filename: string) => void
  ) => {
    const userId = (req as AuthenticatedRequest).userId || "anon";
    const ext = path.extname(file.originalname) || "";
    cb(null, `${userId}-${Date.now()}${ext}`);
  },
});
const allowedMimes = new Set<string>([
  "application/pdf",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
]);
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (
    _req: Request,
    file: Express.Multer.File,
    cb: multer.FileFilterCallback
  ) => {
    if (allowedMimes.has(file.mimetype)) return cb(null, true);
    cb(new Error("Only PDF or DOC/DOCX files are allowed."));
  },
});

// Middleware
app.use(express.json({ limit: "8mb" })); // increased to allow larger base64 proofs
app.use(cookieParser());
app.use("/uploads", express.static(uploadsRoot)); // serve uploaded files

// Add a userId property to the Express Request interface
interface AuthenticatedRequest extends Request {
  userId?: string;
}

// Helpers
function signToken(userId: string) {
  return jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: "7d" });
}
function requireAuth(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  const token = req.cookies?.sid;
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    const payload = jwt.verify(token, JWT_SECRET) as { sub: string };
    req.userId = payload.sub;
    next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
}
function toPublicUser(u: User | null) {
  if (!u) return null;
  const { passwordHash, ...rest } = u;
  return rest;
}

// --- General API Endpoints ---
app.get("/api/health", (_req: Request, res: Response) =>
  res.json({ ok: true })
);

// Debug (DEV ONLY — remove before production)
app.get("/api/debug/users", async (_req: Request, res: Response) => {
  const users = await prisma.user.findMany({
    include: {
      achievements: true,
      registrations: true,
    },
  });
  res.json({ users });
});

// --- Auth API Endpoints ---
app.post("/api/auth/register", async (req: Request, res: Response) => {
  try {
    const { username, email, password } = (req.body || {}) as {
      username?: string;
      email?: string;
      password?: string;
    };
    if (!username || !email || !password) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    const exists = await prisma.user.findFirst({
      where: { OR: [{ email: email.toLowerCase() }, { username }] },
    });
    if (exists) return res.status(409).json({ error: "User already exists" });

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await prisma.user.create({
      data: {
        username,
        email: email.toLowerCase(),
        passwordHash,
        role: "Player",
      },
    });
    const token = signToken(user.id);
    res.cookie("sid", token, { httpOnly: true, sameSite: "lax" });
    return res.status(201).json(toPublicUser(user));
  } catch (e) {
    console.error("REGISTER_ERROR", e);
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/login", async (req: Request, res: Response) => {
  try {
    const { identifier, password } = (req.body || {}) as {
      identifier?: string;
      password?: string;
    };
    if (!identifier || !password) {
      return res.status(400).json({ error: "Missing credentials" });
    }
    const idLower = String(identifier).trim().toLowerCase();
    const user = await prisma.user.findFirst({
      where: { OR: [{ email: idLower }, { username: idLower }] },
    });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const token = signToken(user.id);
    res.cookie("sid", token, { httpOnly: true, sameSite: "lax" });
    return res.json(toPublicUser(user));
  } catch (e) {
    console.error("LOGIN_ERROR", e);
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/logout", (_req: Request, res: Response) => {
  res.clearCookie("sid");
  res.json({ ok: true });
});

// --- User Profile API Endpoint ---
app.get(
  "/api/me",
  requireAuth,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const userId = req.userId as string;
      const user = await prisma.user.findUnique({ where: { id: userId } });
      if (!user) return res.status(404).json({ error: "Not found" });
      res.json(toPublicUser(user));
    } catch (e) {
      console.error("ME_GET_ERROR", e);
      res.status(500).json({ error: "Server error" });
    }
  }
);

app.patch(
  "/api/me",
  requireAuth,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const userId = req.userId as string;
      const {
        name,
        dob,
        gender,
        mobile,
        role,
        sport,
        profilePic,
        height,
        weight,
        bloodgroup,
        address,
      } = (req.body || {}) as Record<string, unknown>;

      if (mobile && !/^[0-9]{10}$/.test(String(mobile))) {
        return res.status(400).json({ error: "Mobile must be 10 digits" });
      }

      const data: any = {};
      if (name !== undefined) data.name = String(name);
      if (dob !== undefined) data.dob = dob ? new Date(String(dob)) : null;
      if (gender !== undefined) data.gender = String(gender);
      if (mobile !== undefined) data.mobile = String(mobile);
      if (role !== undefined) data.role = String(role);
      if (sport !== undefined) data.sport = String(sport);
      if (profilePic !== undefined) data.profilePic = String(profilePic);
      if (height !== undefined)
        data.height = height === null ? null : Number(height);
      if (weight !== undefined)
        data.weight = weight === null ? null : Number(weight);
      if (bloodgroup !== undefined) data.bloodgroup = String(bloodgroup);
      if (address !== undefined) data.address = String(address);

      const updated = await prisma.user.update({ where: { id: userId }, data });
      res.json(toPublicUser(updated));
    } catch (e) {
      console.error("ME_PATCH_ERROR", e);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// --- Achievements API Endpoints ---
app.get(
  "/api/achievements/my",
  requireAuth,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const userId = req.userId as string;
      const achievements = await prisma.achievement.findMany({
        where: { ownerId: userId },
        orderBy: { createdAt: "desc" },
      });
      res.json(achievements);
    } catch (e) {
      console.error("GET_MY_ACHIEVEMENTS_ERROR", e);
      res.status(500).json({ error: "Server error" });
    }
  }
);

app.get(
  "/api/achievements/pending",
  requireAuth,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const coach = await prisma.user.findUnique({ where: { id: req.userId } });
      if (!coach || coach.role !== "Coach" || !coach.sport) {
        return res.status(403).json({ error: "Forbidden" });
      }

      const pendingAchievements = await prisma.achievement.findMany({
        where: {
          status: "PENDING",
          sport: coach.sport,
        },
        include: {
          owner: {
            select: {
              username: true,
            },
          },
        },
        orderBy: { createdAt: "desc" },
      });
      res.json(pendingAchievements);
    } catch (e) {
      console.error("GET_PENDING_ACHIEVEMENTS_ERROR", e);
      res.status(500).json({ error: "Server error" });
    }
  }
);

app.post(
  "/api/achievements",
  requireAuth,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const userId = req.userId as string;
      const { title, date, description, proof, sport, venue } = req.body;

      if (!title || !date || !sport || !venue) {
        return res.status(400).json({ error: "Missing required fields" });
      }

      const newAchievement = await prisma.achievement.create({
        data: {
          title,
          date: new Date(date),
          description,
          proof,
          sport,
          venue,
          ownerId: userId,
          status: "PENDING",
        },
      });
      res.status(201).json(newAchievement);
    } catch (e) {
      console.error("CREATE_ACHIEVEMENT_ERROR", e);
      res.status(500).json({ error: "Server error" });
    }
  }
);

app.put(
  "/api/achievements/:id",
  requireAuth,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const userId = req.userId as string;
      const { id } = req.params;
      const { title, sport, date, venue, description } = req.body;

      const achievement = await prisma.achievement.findUnique({
        where: { id },
      });
      if (!achievement || achievement.ownerId !== userId) {
        return res
          .status(404)
          .json({ error: "Achievement not found or unauthorized" });
      }

      const updatedAchievement = await prisma.achievement.update({
        where: { id },
        data: {
          title,
          sport,
          date: new Date(date),
          venue,
          description,
          updatedAt: new Date(),
        },
      });
      res.json(updatedAchievement);
    } catch (e) {
      console.error("UPDATE_ACHIEVEMENT_ERROR", e);
      res.status(500).json({ error: "Server error" });
    }
  }
);

app.delete(
  "/api/achievements/:id",
  requireAuth,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const userId = req.userId as string;
      const { id } = req.params;

      const achievement = await prisma.achievement.findUnique({
        where: { id },
      });
      if (!achievement || achievement.ownerId !== userId) {
        return res
          .status(404)
          .json({ error: "Achievement not found or unauthorized" });
      }

      if (achievement.status === "APPROVED") {
        return res
          .status(403)
          .json({ error: "Cannot delete an approved achievement." });
      }

      await prisma.achievement.delete({ where: { id } });
      res.status(204).send();
    } catch (e) {
      console.error("DELETE_ACHIEVEMENT_ERROR", e);
      res.status(500).json({ error: "Server error" });
    }
  }
);

app.patch(
  "/api/achievements/:id/verify",
  requireAuth,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const coachId = req.userId as string;
      const { id } = req.params;
      const { decision, reason } = req.body;

      const coach = await prisma.user.findUnique({ where: { id: coachId } });
      const achievement = await prisma.achievement.findUnique({
        where: { id },
      });

      if (!coach || coach.role !== "Coach" || !coach.sport) {
        return res.status(403).json({ error: "Forbidden: Not a coach" });
      }
      if (!achievement) {
        return res.status(404).json({ error: "Achievement not found" });
      }
      if (achievement.sport !== coach.sport) {
        return res.status(403).json({
          error: "Forbidden: Cannot verify achievement for a different sport",
        });
      }

      const updatedAchievement = await prisma.achievement.update({
        where: { id },
        data: {
          status: decision,
          decisionReason: decision === "REJECTED" ? reason : null,
          verifiedById: coach.id,
          verifiedByName: coach.username,
          verifiedAt: new Date(),
        },
      });
      res.json(updatedAchievement);
    } catch (e) {
      console.error("VERIFY_ACHIEVEMENT_ERROR", e);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// --- Onboarding Certificate Endpoints ---
app.post(
  "/api/onboarding/certificate",
  requireAuth,
  upload.single("file"),
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const userId = req.userId as string;
      const file = (req as any).file as Express.Multer.File | undefined;
      const forRole = String(req.body?.forRole || "").trim() || "Coach";
      if (!file) return res.status(400).json({ error: "File is required" });

      const url = `/uploads/certificates/${file.filename}`;
      const doc = await prisma.onboardingDoc.create({
        data: {
          userId,
          forRole,
          fileName: file.originalname,
          mimeType: file.mimetype,
          size: file.size,
          url,
          status: "SUBMITTED",
        },
      });
      res.status(201).json(doc);
    } catch (e) {
      console.error("CERT_UPLOAD_ERROR", e);
      res.status(500).json({ error: "Server error" });
    }
  }
);

app.get(
  "/api/onboarding/certificate",
  requireAuth,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const userId = req.userId as string;
      const doc = await prisma.onboardingDoc.findFirst({
        where: { userId },
        orderBy: { uploadedAt: "desc" },
      });
      res.json(doc || null);
    } catch (e) {
      console.error("CERT_GET_ERROR", e);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// --- Coach Reports Endpoint ---
app.get(
  "/api/reports/coach",
  requireAuth,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const coachId = req.userId as string;
      const coach = await prisma.user.findUnique({ where: { id: coachId } });

      if (!coach || coach.role !== "Coach" || !coach.sport) {
        return res.status(403).json({ error: "Forbidden" });
      }

      const thirtyDaysAgo = new Date(
        new Date().setDate(new Date().getDate() - 30)
      );
      const sevenDaysAgo = new Date(
        new Date().setDate(new Date().getDate() - 7)
      );
      const sevenDaysFromNow = new Date(
        new Date().setDate(new Date().getDate() + 7)
      );

      const achievementsCount = await prisma.achievement.groupBy({
        by: ["status"],
        where: { owner: { sport: coach.sport, role: "Player" } },
        _count: { status: true },
      });

      const registrationsCount = await prisma.tournamentRegistration.groupBy({
        by: ["regStatus"],
        where: { player: { sport: coach.sport, role: "Player" } },
        _count: { regStatus: true },
      });

      const upcomingSessions7d = await prisma.schedule.count({
        where: {
          coachId: coach.id,
          date: { gte: new Date(), lte: sevenDaysFromNow },
        },
      });

      const scheduleRequests30d = await prisma.scheduleRequest.findMany({
        where: {
          schedule: { coachId: coach.id },
          createdAt: { gte: thirtyDaysAgo },
        },
      });

      const activePlayerIds = await prisma.scheduleRequest.findMany({
        where: {
          schedule: { coachId: coach.id },
          createdAt: { gte: sevenDaysAgo },
        },
        distinct: ["playerId"],
        select: { playerId: true },
      });

      const kpis = {
        achievementsApproved:
          achievementsCount.find((c) => c.status === "APPROVED")?._count
            .status || 0,
        achievementsPending:
          achievementsCount.find((c) => c.status === "PENDING")?._count
            .status || 0,
        regPending:
          registrationsCount.find((c) => c.regStatus === "PENDING")?._count
            .regStatus || 0,
        regConfirmed:
          registrationsCount.find((c) => c.regStatus === "CONFIRMED")?._count
            .regStatus || 0,
        upcomingSessions7d: upcomingSessions7d,
        activePlayersThisWeek: activePlayerIds.length,
        attendanceRatePct:
          scheduleRequests30d.length > 0
            ? Math.round(
                (scheduleRequests30d.filter((r) => r.status === "APPROVED")
                  .length /
                  scheduleRequests30d.length) *
                  100
              )
            : null,
      };

      res.json(kpis);
    } catch (e) {
      console.error("COACH_REPORTS_ERROR", e);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Static frontend
app.use(express.static(staticRoot));

/**
 * Start server with port auto‑fallback.
 */
const START_PORT = Number(process.env.PORT) || 3001;

function startServer(port: number) {
  const server = app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
  });

  server.on("error", (err: any) => {
    if (err && err.code === "EADDRINUSE") {
      const nextPort = port + 1;
      console.warn(`Port ${port} in use, trying ${nextPort}...`);
      startServer(nextPort);
    } else {
      console.error("Server error:", err);
      process.exit(1);
    }
  });
}

startServer(START_PORT);
