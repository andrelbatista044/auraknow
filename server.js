const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const { supabase } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'auraknow-super-secret-key';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Middlewares
const verifyToken = async (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Não autorizado' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const { data: user } = await supabase.from('users').select('is_active').eq('id', decoded.id).single();
        if (!user || !user.is_active) {
            res.clearCookie('token');
            return res.status(403).json({ error: 'Acesso bloqueado' });
        }
        req.user = decoded;
        next();
    } catch (err) {
        res.clearCookie('token');
        return res.status(401).json({ error: 'Sessão inválida' });
    }
};

const isAdmin = async (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Não autorizado' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const { data: user } = await supabase.from('users').select('role, is_active').eq('id', decoded.id).single();
        if (user && user.role === 'admin' && user.is_active) {
            req.user = decoded;
            return next();
        }
        res.status(403).json({ error: 'Acesso negado' });
    } catch (err) {
        res.clearCookie('token');
        res.status(401).json({ error: 'Sessão inválida' });
    }
};

// --- AUTH ---
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const { data: user, error } = await supabase.from('users').select('*').eq('email', email).single();
        if (error || !user) return res.status(404).json({ error: 'Usuário não encontrado' });
        if (!user.is_active) return res.status(403).json({ error: 'Acesso bloqueado.' });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: 'Senha incorreta' });
        const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
        res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none', maxAge: 7 * 24 * 60 * 60 * 1000 });
        res.json({ success: true, role: user.role, name: user.name });
    } catch (err) { res.status(500).json({ error: 'Erro no servidor' }); }
});
app.post('/api/logout', (req, res) => { res.clearCookie('token'); res.json({ success: true }); });
app.get('/api/me', verifyToken, async (req, res) => {
    const { data: user } = await supabase.from('users').select('id, name, role, is_active').eq('id', req.user.id).single();
    res.json({ ...user, isActive: user.is_active });
});

// --- CURSOS ---
app.get('/api/courses', verifyToken, async (req, res) => {
    if (req.user.role === 'admin') {
        const { data } = await supabase.from('courses').select('*').order('created_at', { ascending: false });
        return res.json(data);
    }
    const { data } = await supabase.from('enrollments').select('courses(*)').eq('user_id', req.user.id);
    res.json(data.map(item => item.courses));
});
app.post('/api/admin/courses', isAdmin, async (req, res) => {
    const { data } = await supabase.from('courses').insert([req.body]).select();
    res.json(data[0]);
});
app.put('/api/admin/courses/:id', isAdmin, async (req, res) => {
    await supabase.from('courses').update(req.body).eq('id', req.params.id);
    res.json({ success: true });
});
app.delete('/api/admin/courses/:id', isAdmin, async (req, res) => {
    await supabase.from('courses').delete().eq('id', req.params.id);
    res.json({ success: true });
});

// --- MATÉRIAS ---
app.get('/api/courses/:id/subjects', verifyToken, async (req, res) => {
    const { data } = await supabase.from('subjects').select('*').eq('course_id', req.params.id).order('order', { ascending: true });
    res.json(data);
});
app.post('/api/admin/subjects', isAdmin, async (req, res) => {
    const { data } = await supabase.from('subjects').insert([req.body]).select();
    res.json(data[0]);
});
app.delete('/api/admin/subjects/:id', isAdmin, async (req, res) => {
    await supabase.from('subjects').delete().eq('id', req.params.id);
    res.json({ success: true });
});

// --- MÓDULOS ---
app.get('/api/subjects/:id/modules', verifyToken, async (req, res) => {
    const { data } = await supabase.from('modules').select('*').eq('subject_id', req.params.id).order('order', { ascending: true });
    res.json(data);
});
app.post('/api/admin/modules', isAdmin, async (req, res) => {
    const { data } = await supabase.from('modules').insert([req.body]).select();
    res.json(data[0]);
});
app.delete('/api/admin/modules/:id', isAdmin, async (req, res) => {
    await supabase.from('modules').delete().eq('id', req.params.id);
    res.json({ success: true });
});

// --- AULAS ---
app.get('/api/modules/:id/lessons', verifyToken, async (req, res) => {
    const { data } = await supabase.from('lessons').select('*').eq('module_id', req.params.id).order('order', { ascending: true });
    res.json(data);
});
app.post('/api/admin/lessons', isAdmin, async (req, res) => {
    const { data } = await supabase.from('lessons').insert([req.body]).select();
    res.json(data[0]);
});
app.put('/api/admin/lessons/:id', isAdmin, async (req, res) => {
    await supabase.from('lessons').update(req.body).eq('id', req.params.id);
    res.json({ success: true });
});
app.delete('/api/admin/lessons/:id', isAdmin, async (req, res) => {
    await supabase.from('lessons').delete().eq('id', req.params.id);
    res.json({ success: true });
});

// BUSCAR AULAS/MÓDULOS SEM PAI (Legado)
app.get('/api/courses/:id/orphan-modules', verifyToken, async (req, res) => {
    const { data } = await supabase.from('modules').select('*').eq('course_id', req.params.id).is('subject_id', null).order('order', { ascending: true });
    res.json(data);
});
app.get('/api/courses/:id/orphan-lessons', verifyToken, async (req, res) => {
    const { data } = await supabase.from('lessons').select('*').eq('course_id', req.params.id).is('module_id', null).order('order', { ascending: true });
    res.json(data);
});

// --- ADMIN USERS ---
app.get('/api/admin/users', isAdmin, async (req, res) => {
    const { data } = await supabase.from('users').select('id, name, email, role, is_active').order('created_at', { ascending: false });
    res.json(data.map(u => ({ ...u, isActive: u.is_active })));
});
app.post('/api/admin/create-user', isAdmin, async (req, res) => {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    await supabase.from('users').insert([{ ...req.body, password: hashedPassword }]);
    res.json({ success: true });
});
app.post('/api/admin/toggle-status', isAdmin, async (req, res) => {
    const { data: user } = await supabase.from('users').select('is_active').eq('id', req.body.userId).single();
    await supabase.from('users').update({ is_active: !user.is_active }).eq('id', req.body.userId);
    res.json({ success: true });
});
app.delete('/api/admin/delete-user', isAdmin, async (req, res) => {
    await supabase.from('users').delete().eq('id', req.body.userId);
    res.json({ success: true });
});
app.post('/api/admin/enroll', isAdmin, async (req, res) => {
    await supabase.from('enrollments').insert([req.body]);
    res.json({ success: true });
});

app.listen(PORT, () => console.log(`🚀 AuraKnow LMS v3 (Materias) na porta ${PORT}`));
