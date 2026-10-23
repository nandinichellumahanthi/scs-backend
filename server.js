import dns from 'node:dns'
dns.setServers(['8.8.8.8', '1.1.1.1'])
import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import mongoose from 'mongoose'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

const { MONGO_URI, JWT_SECRET = 'dev-secret', ADMIN_EMAIL = 'admin@gvpihlr.edu', ADMIN_PASSWORD = 'Admin@123', CLIENT_ORIGIN = '*', PORT = 5000 } = process.env
if (!MONGO_URI) { console.error('Missing MONGO_URI. Copy .env.example to .env and fill it in.'); process.exit(1) }

const S = mongoose.Schema, ID = S.Types.ObjectId
const User = mongoose.model('User', new S({
  name: String, email: { type: String, unique: true }, password: String,
  role: { type: String, enum: ['student', 'faculty', 'admin'] }, rollNo: String, department: String,
  registered: { type: Boolean, default: true },
}))
const Category = mongoose.model('Category', new S({ name: { type: String, unique: true }, department: String, faculty: { type: ID, ref: 'User', default: null } }))
const Complaint = mongoose.model('Complaint', new S({
  code: String, title: String, description: String, category: String, location: String, priority: String,
  status: { type: String, default: 'Submitted' }, evidence: String,
  student: { type: ID, ref: 'User' }, assignedTo: { type: ID, ref: 'User', default: null },
  comments: [{ by: String, role: String, text: String, at: { type: Date, default: Date.now } }],
}, { timestamps: true }))

const STATUSES = ['Submitted', 'Under Review', 'In Progress', 'Resolved', 'Escalated']
const norm = (e) => String(e || '').trim().toLowerCase()
const same = (a, b) => String(a) === String(b)
const sign = (u) => jwt.sign({ id: u._id }, JWT_SECRET, { expiresIn: '7d' })
const pub = (u) => ({ _id: u._id, name: u.name, email: u.email, role: u.role, department: u.department, rollNo: u.rollNo })
const pop = (q) => q.populate('student', 'name email rollNo').populate('assignedTo', 'name email department')
const wrap = (fn) => (req, res) => fn(req, res).catch((e) => { console.error(e); res.status(500).json({ error: 'Server error' }) })
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg })

const auth = (...roles) => async (req, res, next) => {
  try {
    const p = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), JWT_SECRET)
    req.user = await User.findById(p.id)
    if (!req.user || (roles.length && !roles.includes(req.user.role))) throw new Error('no')
    next()
  } catch { bad(res, 'Please log in again', 401) }
}

const app = express()
app.use(cors({ origin: CLIENT_ORIGIN === '*' ? true : CLIENT_ORIGIN.split(',').map((s) => s.trim()) }))
app.use(express.json({ limit: '8mb' }))
app.get('/', (_q, res) => res.json({ ok: true, service: 'Smart Complaint System API' }))

// ---------- auth ----------
app.post('/api/auth/register', wrap(async (req, res) => {
  const { name, rollNo, password } = req.body, email = norm(req.body.email)
  if (!name || !email || !password || password.length < 6) return bad(res, 'Name, email and a password of 6+ characters are required')
  if (await User.findOne({ email })) return bad(res, 'This email is already registered', 409)
  const u = await User.create({ name, email, rollNo, password: await bcrypt.hash(password, 10), role: 'student' })
  res.json({ token: sign(u), user: pub(u) })
}))

app.post('/api/auth/register-faculty', wrap(async (req, res) => {
  const { password } = req.body
  const u = await User.findOne({ email: norm(req.body.email), role: 'faculty' })
  if (!u) return bad(res, 'This email was not added by the admin. Ask the admin to add you first.', 403)
  if (u.registered) return bad(res, 'You are already registered. Please log in.', 409)
  if (!password || password.length < 6) return bad(res, 'Password must be at least 6 characters')
  u.password = await bcrypt.hash(password, 10); u.registered = true; await u.save()
  res.json({ token: sign(u), user: pub(u) })
}))

app.post('/api/auth/login', wrap(async (req, res) => {
  const id = String(req.body.email || '').trim()
  const u = await User.findOne({ $or: [{ email: norm(id) }, { rollNo: id }] })
  const ok = u && u.registered && u.password && (await bcrypt.compare(req.body.password || '', u.password))
  if (!ok || (req.body.role && u.role !== req.body.role)) return bad(res, 'Wrong email, password or role', 401)
  res.json({ token: sign(u), user: pub(u) })
}))

app.get('/api/auth/me', auth(), (req, res) => res.json(pub(req.user)))

// ---------- categories & faculty (admin) ----------
app.get('/api/categories', auth(), wrap(async (_q, res) => res.json(await Category.find().populate('faculty', 'name email').sort('_id'))))

app.post('/api/categories', auth('admin'), wrap(async (req, res) => {
  const name = String(req.body.name || '').trim()
  if (!name) return bad(res, 'Category name is required')
  if (await Category.findOne({ name })) return bad(res, 'Category already exists', 409)
  res.json(await Category.create({ name, department: req.body.department || 'Administration' }))
}))

app.patch('/api/categories/:id', auth('admin'), wrap(async (req, res) => {
  const cat = await Category.findById(req.params.id)
  if (!cat) return bad(res, 'Category not found', 404)
  cat.faculty = req.body.faculty || null
  if (req.body.department) cat.department = req.body.department
  await cat.save()
  if (cat.faculty) await Complaint.updateMany({ category: cat.name, assignedTo: null }, { assignedTo: cat.faculty })
  res.json(await cat.populate('faculty', 'name email'))
}))

app.get('/api/faculty', auth('admin'), wrap(async (_q, res) => res.json(await User.find({ role: 'faculty' }).select('-password').sort('_id'))))

app.post('/api/faculty', auth('admin'), wrap(async (req, res) => {
  const { name, department } = req.body, email = norm(req.body.email)
  if (!name || !email) return bad(res, 'Name and email are required')
  if (await User.findOne({ email })) return bad(res, 'This email already exists', 409)
  const u = await User.create({ name, email, department, role: 'faculty', registered: false })
  res.json(pub(u))
}))

app.delete('/api/faculty/:id', auth('admin'), wrap(async (req, res) => {
  await User.deleteOne({ _id: req.params.id, role: 'faculty' })
  await Category.updateMany({ faculty: req.params.id }, { faculty: null })
  res.json({ ok: true })
}))

// ---------- complaints ----------
const canSee = (u, c) => u.role === 'admin' || (u.role === 'student' && same(c.student._id, u._id)) || (u.role === 'faculty' && c.assignedTo && same(c.assignedTo._id, u._id))
async function getC(req, res) {
  let c = null
  try { c = await pop(Complaint.findById(req.params.id)) } catch { /* bad id */ }
  if (!c || !canSee(req.user, c)) { bad(res, 'Complaint not found', 404); return null }
  return c
}
const fresh = (id) => pop(Complaint.findById(id))

app.get('/api/complaints', auth(), wrap(async (req, res) => {
  const r = req.user.role
  const filter = r === 'student' ? { student: req.user._id } : r === 'faculty' ? { assignedTo: req.user._id } : {}
  res.json(await pop(Complaint.find(filter).select('-evidence -comments').sort('-createdAt')))
}))

app.post('/api/complaints', auth('student'), wrap(async (req, res) => {
  const { title, description, category, location, priority, evidence } = req.body
  if (!title || !description || !category) return bad(res, 'Category, title and description are required')
  const cat = await Category.findOne({ name: category })
  const n = await Complaint.countDocuments()
  const c = await Complaint.create({
    code: `C${String(123 + n).padStart(5, '0')}`, title, description, category, location, evidence,
    priority: ['Low', 'Medium', 'High', 'Urgent'].includes(priority) ? priority : 'Low',
    student: req.user._id, assignedTo: cat?.faculty || null,
  })
  res.json(await fresh(c._id))
}))

app.get('/api/complaints/:id', auth(), wrap(async (req, res) => { const c = await getC(req, res); if (c) res.json(c) }))

app.patch('/api/complaints/:id/status', auth('faculty', 'admin'), wrap(async (req, res) => {
  const c = await getC(req, res); if (!c) return
  if (!STATUSES.includes(req.body.status)) return bad(res, 'Invalid status')
  c.status = req.body.status
  c.comments.push({ by: 'System', role: 'system', text: `Status changed to ${c.status} by ${req.user.name}` })
  await c.save(); res.json(await fresh(c._id))
}))

app.patch('/api/complaints/:id/assign', auth('admin'), wrap(async (req, res) => {
  const c = await getC(req, res); if (!c) return
  c.assignedTo = req.body.assignedTo || null; await c.save(); res.json(await fresh(c._id))
}))

app.post('/api/complaints/:id/comments', auth(), wrap(async (req, res) => {
  const c = await getC(req, res); if (!c) return
  const text = String(req.body.text || '').trim()
  if (!text) return bad(res, 'Write something first')
  c.comments.push({ by: req.user.name, role: req.user.role, text }); await c.save()
  res.json(await fresh(c._id))
}))

// ---------- start ----------
const DEFAULTS = [['Water Supply', 'Maintenance'], ['Lab Equipment', 'Technical Support'], ['Hostel', 'Hostel Administration'], ['Mess & Canteen', 'Food Services'], ['Classroom / Infrastructure', 'Infrastructure'], ['Electrical', 'Maintenance'], ['Internet / Wi-Fi', 'IT Department'], ['Transport', 'Transport'], ['Cleanliness / Sanitation', 'Housekeeping'], ['Other', 'Administration']]
await mongoose.connect(MONGO_URI)
for (const [name, department] of DEFAULTS) await Category.updateOne({ name }, { $setOnInsert: { department } }, { upsert: true })
if (!(await User.findOne({ role: 'admin' }))) await User.create({ name: 'Admin User', email: norm(ADMIN_EMAIL), password: await bcrypt.hash(ADMIN_PASSWORD, 10), role: 'admin' })
app.listen(PORT, () => console.log(`API running on port ${PORT}`))
