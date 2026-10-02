const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(cors());
app.use('/api', rateLimit({ windowMs: 60 * 1000, max: 200 }));

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(e => console.log('❌ Mongo error:', e.message));

const User = mongoose.model('User', new mongoose.Schema({
  phone: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  deviceId: { type: String, unique: true, required: true },
  name: String,
  pendingPoints: { type: Number, default: 0 },
  balance: { type: Number, default: 0 },
  totalEarned: { type: Number, default: 0 },
  isBanned: { type: Boolean, default: false },
  referralCode: { type: String, unique: true },
  referredBy: String,
}, { timestamps: true }));

const Task = mongoose.model('Task', new mongoose.Schema({
  title: String, description: String, depositAmt: Number, rewardAmt: Number,
  link: String, logo: String, category: { type: String, default: 'betting' },
  isActive: { type: Boolean, default: true }, completed: { type: Number, default: 0 },
}, { timestamps: true }));

const Submission = mongoose.model('Submission', new mongoose.Schema({
  phone: String, taskId: mongoose.Schema.Types.ObjectId, taskTitle: String,
  siteUsername: String, transactionId: String, screenshotUrl: String,
  rewardAmt: Number,
  status: { type: String, enum: ['PENDING','APPROVED','REJECTED'], default: 'PENDING' },
  rejectReason: String,
}, { timestamps: true }));

const Withdrawal = mongoose.model('Withdrawal', new mongoose.Schema({
  phone: String, amount: Number, paymentMethod: String, accountNumber: String,
  status: { type: String, enum: ['PENDING','APPROVED','REJECTED'], default: 'PENDING' },
  rejectReason: String,
}, { timestamps: true }));

const Notice = mongoose.model('Notice', new mongoose.Schema({
  title: String, body: String, isActive: { type: Boolean, default: true }
}, { timestamps: true }));

const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
};

const adminAuth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    const d = jwt.verify(token, process.env.JWT_SECRET);
    if (d.role !== 'admin') throw new Error();
    next();
  } catch { res.status(403).json({ error: 'Admin only' }); }
};

// 🎁 CONFIG
const WELCOME_BONUS = 50;
const MIN_WITHDRAW = 100;
const REFERRAL_BONUS = 10;

app.post('/api/register', async (req, res) => {
  try {
    const { phone, password, deviceId, name, referralCode } = req.body;
    if (!phone || !password || !deviceId) return res.status(400).json({ error: 'Missing fields' });
    if (await User.findOne({ deviceId })) return res.status(400).json({ error: 'একটি ডিভাইসে একটাই একাউন্ট!' });
    if (await User.findOne({ phone })) return res.status(400).json({ error: 'এই নাম্বারে একাউন্ট আছে!' });

    const hash = await bcrypt.hash(password, 10);
    const myCode = 'EM' + Math.random().toString(36).slice(2, 8).toUpperCase();
    
    const user = await User.create({
      phone, password: hash, deviceId, name, referralCode: myCode, referredBy: referralCode,
      balance: WELCOME_BONUS, totalEarned: WELCOME_BONUS
    });

    if (referralCode) {
      const ref = await User.findOne({ referralCode });
      if (ref) await User.updateOne({ _id: ref._id }, { $inc: { balance: REFERRAL_BONUS, totalEarned: REFERRAL_BONUS } });
    }

    const token = jwt.sign({ id: user._id, phone, role: 'user' }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({
      message: `সফলভাবে রেজিস্ট্রেশন হয়েছে! 🎁 ${WELCOME_BONUS}৳ বোনাস পেয়েছ!`,
      token,
      user: { phone, name, balance: WELCOME_BONUS, pendingPoints: 0, referralCode: myCode }
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/login', async (req, res) => {
  const { phone, password, deviceId } = req.body;
  const user = await User.findOne({ phone });
  if (!user) return res.status(400).json({ error: 'ইউজার নেই!' });
  if (user.isBanned) return res.status(403).json({ error: 'একাউন্ট ব্যান!' });
  if (deviceId && user.deviceId !== deviceId) return res.status(403).json({ error: 'ভিন্ন ডিভাইস!' });
  if (!await bcrypt.compare(password, user.password)) return res.status(400).json({ error: 'পাসওয়ার্ড ভুল!' });

  const token = jwt.sign({ id: user._id, phone, role: 'user' }, process.env.JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { phone, name: user.name, balance: user.balance, pendingPoints: user.pendingPoints, referralCode: user.referralCode } });
});

app.get('/api/me', auth, async (req, res) => {
  res.json(await User.findOne({ phone: req.user.phone }).select('-password'));
});

app.get('/api/tasks', auth, async (req, res) => {
  const tasks = await Task.find({ isActive: true }).sort({ createdAt: -1 });
  const mySubs = await Submission.find({ phone: req.user.phone }).select('taskId status');
  res.json({ tasks, mySubs });
});

app.post('/api/submit-task', auth, async (req, res) => {
  const { taskId, siteUsername, transactionId, screenshotUrl } = req.body;
  const task = await Task.findById(taskId);
  if (!task) return res.status(404).json({ error: 'টাস্ক নেই!' });
  const dup = await Submission.findOne({ phone: req.user.phone, taskId, status: { $ne: 'REJECTED' } });
  if (dup) return res.status(400).json({ error: 'এই টাস্ক আগেই সাবমিট করেছ!' });

  const sub = await Submission.create({
    phone: req.user.phone, taskId, taskTitle: task.title,
    siteUsername, transactionId, screenshotUrl, rewardAmt: task.rewardAmt
  });
  await User.updateOne({ phone: req.user.phone }, { $inc: { pendingPoints: task.rewardAmt } });
  await Task.updateOne({ _id: task._id }, { $inc: { completed: 1 } });
  res.json({ message: 'সাবমিট সফল! এডমিন ভেরিফাই করবে।', sub });
});

app.get('/api/my-submissions', auth, async (req, res) => {
  res.json(await Submission.find({ phone: req.user.phone }).sort({ createdAt: -1 }));
});

app.post('/api/withdraw', auth, async (req, res) => {
  const { amount, paymentMethod, accountNumber } = req.body;
  const user = await User.findOne({ phone: req.user.phone });
  if (amount < MIN_WITHDRAW) return res.status(400).json({ error: `⚠️ সর্বনিম্ন ${MIN_WITHDRAW}৳ withdraw করতে হবে!` });
  if (user.balance < amount) return res.status(400).json({ error: 'ব্যালেন্স কম!' });

  await User.updateOne({ phone: user.phone }, { $inc: { balance: -amount } });
  const w = await Withdrawal.create({ phone: user.phone, amount, paymentMethod, accountNumber });
  res.json({ message: 'উইথড্র রিকোয়েস্ট পাঠানো হয়েছে!', w });
});

app.get('/api/my-withdrawals', auth, async (req, res) => {
  res.json(await Withdrawal.find({ phone: req.user.phone }).sort({ createdAt: -1 }));
});

app.get('/api/notices', auth, async (req, res) => {
  res.json(await Notice.find({ isActive: true }).sort({ createdAt: -1 }));
});

app.get('/api/config', (req, res) => {
  res.json({ welcomeBonus: WELCOME_BONUS, minWithdraw: MIN_WITHDRAW, referralBonus: REFERRAL_BONUS });
});

app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username !== process.env.ADMIN_USER || password !== process.env.ADMIN_PASS)
    return res.status(401).json({ error: 'ভুল ক্রেডেনশিয়াল' });
  res.json({ token: jwt.sign({ role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '7d' }) });
});

app.get('/api/admin/stats', adminAuth, async (req, res) => {
  const [users, subs, ws, pendingSub, pendingW] = await Promise.all([
    User.countDocuments(), Submission.countDocuments(), Withdrawal.countDocuments(),
    Submission.countDocuments({ status: 'PENDING' }), Withdrawal.countDocuments({ status: 'PENDING' }),
  ]);
  const totalPaid = await Withdrawal.aggregate([{ $match: { status: 'APPROVED' } }, { $group: { _id: null, t: { $sum: '$amount' } } }]);
  res.json({ users, submissions: subs, withdrawals: ws, pendingSub, pendingW, totalPaid: totalPaid[0]?.t || 0, welcomeBonus: WELCOME_BONUS, minWithdraw: MIN_WITHDRAW });
});

app.get('/api/admin/users', adminAuth, async (req, res) => {
  res.json(await User.find().select('-password').sort({ createdAt: -1 }));
});

app.post('/api/admin/ban-user', adminAuth, async (req, res) => {
  const { phone, ban } = req.body;
  await User.updateOne({ phone }, { isBanned: ban });
  res.json({ message: ban ? 'ব্যান করা হয়েছে' : 'আনব্যান করা হয়েছে' });
});

app.post('/api/admin/add-balance', adminAuth, async (req, res) => {
  const { phone, amount } = req.body;
  await User.updateOne({ phone }, { $inc: { balance: amount, totalEarned: amount } });
  res.json({ message: 'ব্যালেন্স যোগ হয়েছে' });
});

app.post('/api/admin/add-task', adminAuth, async (req, res) => {
  res.json(await Task.create(req.body));
});
app.get('/api/admin/tasks', adminAuth, async (req, res) => {
  res.json(await Task.find().sort({ createdAt: -1 }));
});
app.put('/api/admin/task/:id', adminAuth, async (req, res) => {
  res.json(await Task.findByIdAndUpdate(req.params.id, req.body, { new: true }));
});
app.delete('/api/admin/task/:id', adminAuth, async (req, res) => {
  await Task.findByIdAndDelete(req.params.id);
  res.json({ message: 'ডিলিট হয়েছে' });
});

app.get('/api/admin/submissions', adminAuth, async (req, res) => {
  res.json(await Submission.find().sort({ createdAt: -1 }));
});
app.post('/api/admin/verify-task', adminAuth, async (req, res) => {
  const { subId, status, rejectReason } = req.body;
  const sub = await Submission.findById(subId);
  if (!sub || sub.status !== 'PENDING') return res.status(400).json({ error: 'Already processed' });
  sub.status = status;
  sub.rejectReason = rejectReason;
  await sub.save();
  const user = await User.findOne({ phone: sub.phone });
  user.pendingPoints -= sub.rewardAmt;
  if (status === 'APPROVED') {
    user.balance += sub.rewardAmt;
    user.totalEarned += sub.rewardAmt;
  }
  await user.save();
  res.json({ message: `Task ${status}`, sub });
});

app.get('/api/admin/withdrawals', adminAuth, async (req, res) => {
  res.json(await Withdrawal.find().sort({ createdAt: -1 }));
});
app.post('/api/admin/verify-withdraw', adminAuth, async (req, res) => {
  const { wId, status, rejectReason } = req.body;
  const w = await Withdrawal.findById(wId);
  if (!w || w.status !== 'PENDING') return res.status(400).json({ error: 'Already processed' });
  w.status = status;
  w.rejectReason = rejectReason;
  await w.save();
  if (status === 'REJECTED') {
    await User.updateOne({ phone: w.phone }, { $inc: { balance: w.amount } });
  }
  res.json({ message: `Withdraw ${status}`, w });
});

app.post('/api/admin/notice', adminAuth, async (req, res) => {
  res.json(await Notice.create(req.body));
});
app.get('/api/admin/notices', adminAuth, async (req, res) => {
  res.json(await Notice.find().sort({ createdAt: -1 }));
});
app.delete('/api/admin/notice/:id', adminAuth, async (req, res) => {
  await Notice.findByIdAndDelete(req.params.id);
  res.json({ message: 'ডিলিট' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 EARN MONEY Backend on port ${PORT}`));
