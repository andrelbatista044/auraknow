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

// Middleware de Autenticação via JWT
const verifyToken = async (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Não autorizado' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // CHECAGEM DE BLOQUEIO OBRIGATÓRIA EM CADA REQUISIÇÃO
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

        const token = jwt.sign(
            { id: user.id, role: user.role, name: user.name },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.cookie('token', token, {
            httpOnly: true,
            secure: true, // Forçado para Vercel (HTTPS)
            sameSite: 'none', // Necessário para alguns navegadores em domínios diferentes
            maxAge: 7 * 24 * 60 * 60 * 1000 
        });
        
        res.json({ success: true, role: user.role, name: user.name });
    } catch (err) {
        res.status(500).json({ error: 'Erro no servidor' });
    }
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ success: true });
});

app.get('/api/me', verifyToken, async (req, res) => {
    const { data: user } = await supabase.from('users').select('id, name, role, is_active').eq('id', req.user.id).single();
    res.json({ ...user, isActive: user.is_active });
});

// Rotas Administrativas
app.get('/api/admin/users', isAdmin, async (req, res) => {
    const { data: users } = await supabase.from('users').select('id, name, email, role, is_active').order('created_at', { ascending: false });
    const mappedUsers = users.map(u => ({ ...u, isActive: u.is_active }));
    res.json(mappedUsers);
});

app.post('/api/admin/create-user', isAdmin, async (req, res) => {
    const { name, email, password, role } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const { error } = await supabase.from('users').insert([{ name, email, password: hashedPassword, role }]);
        if (error) throw error;
        res.json({ success: true });
    } catch (err) {
        res.status(400).json({ error: 'Erro ao criar usuário ou email duplicado' });
    }
});

app.post('/api/admin/toggle-status', isAdmin, async (req, res) => {
    const { userId } = req.body;
    const { data: user } = await supabase.from('users').select('is_active').eq('id', userId).single();
    if (user) {
        const { error } = await supabase.from('users').update({ is_active: !user.is_active }).eq('id', userId);
        if (error) return res.status(500).json({ error: 'Erro ao atualizar' });
        res.json({ success: true });
    } else {
        res.status(404).json({ error: 'Usuário não encontrado' });
    }
});

// NOVA ROTA: RESET DE SENHA PELO ADMIN
app.post('/api/admin/reset-password', isAdmin, async (req, res) => {
    const { userId, newPassword } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        const { error } = await supabase.from('users').update({ password: hashedPassword }).eq('id', userId);
        if (error) throw error;
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Erro ao redefinir senha' });
    }
});

app.listen(PORT, () => {
    console.log(`🚀 AuraKnow Vercel Edition rodando na porta ${PORT}`);
});
