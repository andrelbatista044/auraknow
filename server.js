const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const { supabase } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'auraknow-super-secret-key';

// Configurações
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

// Rotas de Autenticação
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

// --- GESTÃO DE CURSOS ---

// Listar Cursos (Admin vê tudo, Aluno vê só os dele)
app.get('/api/courses', verifyToken, async (req, res) => {
    try {
        if (req.user.role === 'admin') {
            const { data } = await supabase.from('courses').select('*').order('created_at', { ascending: false });
            return res.json(data);
        } else {
            const { data } = await supabase.from('enrollments').select('courses(*)').eq('user_id', req.user.id);
            return res.json(data.map(item => item.courses));
        }
    } catch (err) { res.status(500).json({ error: 'Erro ao buscar cursos' }); }
});

// Criar Curso (Admin)
app.post('/api/admin/courses', isAdmin, async (req, res) => {
    const { title, description, thumbnail } = req.body;
    const { data, error } = await supabase.from('courses').insert([{ title, description, thumbnail }]).select();
    if (error) return res.status(400).json({ error: error.message });
    res.json(data[0]);
});

// Criar Aula (Admin)
app.post('/api/admin/lessons', isAdmin, async (req, res) => {
    const { course_id, title, video_url, content, order } = req.body;
    const { data, error } = await supabase.from('lessons').insert([{ course_id, title, video_url, content, order }]).select();
    if (error) return res.status(400).json({ error: error.message });
    res.json(data[0]);
});

// Matricular Aluno (Admin)
app.post('/api/admin/enroll', isAdmin, async (req, res) => {
    const { user_id, course_id } = req.body;
    const { error } = await supabase.from('enrollments').insert([{ user_id, course_id }]);
    if (error) return res.status(400).json({ error: 'Aluno já matriculado ou dados inválidos' });
    res.json({ success: true });
});

// Ver Aulas de um Curso (Se matriculado ou Admin)
app.get('/api/courses/:id/lessons', verifyToken, async (req, res) => {
    const courseId = req.params.id;
    if (req.user.role !== 'admin') {
        const { data: enrollment } = await supabase.from('enrollments').select('*').eq('user_id', req.user.id).eq('course_id', courseId).single();
        if (!enrollment) return res.status(403).json({ error: 'Você não tem acesso a este curso' });
    }
    const { data: lessons } = await supabase.from('lessons').select('*').eq('course_id', courseId).order('order', { ascending: true });
    res.json(lessons);
});

// --- GESTÃO DE USUÁRIOS ---
app.get('/api/admin/users', isAdmin, async (req, res) => {
    const { data: users } = await supabase.from('users').select('id, name, email, role, is_active').order('created_at', { ascending: false });
    res.json(users.map(u => ({ ...u, isActive: u.is_active })));
});

app.post('/api/admin/create-user', isAdmin, async (req, res) => {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const { error } = await supabase.from('users').insert([{ ...req.body, password: hashedPassword }]);
    if (error) return res.status(400).json({ error: 'Erro ao criar' });
    res.json({ success: true });
});

app.post('/api/admin/toggle-status', isAdmin, async (req, res) => {
    const { userId } = req.body;
    const { data: user } = await supabase.from('users').select('is_active').eq('id', userId).single();
    if (user) {
        await supabase.from('users').update({ is_active: !user.is_active }).eq('id', userId);
        res.json({ success: true });
    } else res.status(404).json({ error: 'Não encontrado' });
});

app.post('/api/admin/reset-password', isAdmin, async (req, res) => {
    const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);
    await supabase.from('users').update({ password: hashedPassword }).eq('id', req.body.userId);
    res.json({ success: true });
});

app.delete('/api/admin/delete-user', isAdmin, async (req, res) => {
    if (req.body.userId === req.user.id) return res.status(400).json({ error: 'Não pode apagar a si mesmo' });
    await supabase.from('users').delete().eq('id', req.body.userId);
    res.json({ success: true });
});

app.listen(PORT, () => console.log(`🚀 AuraKnow LMS Edition na porta ${PORT}`));
