const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const { supabase } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// Configurações
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'auraknow-vercel-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } 
}));

// Middlewares
const isAdmin = async (req, res, next) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
    const { data: user } = await supabase.from('users').select('role').eq('id', req.session.userId).single();
    if (user && user.role === 'admin') return next();
    res.status(403).json({ error: 'Acesso negado' });
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

        req.session.userId = user.id;
        req.session.userRole = user.role;
        
        res.json({ success: true, role: user.role, name: user.name });
    } catch (err) {
        res.status(500).json({ error: 'Erro no servidor' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/api/me', async (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Offline' });
    const { data: user } = await supabase.from('users').select('id, name, role, is_active').eq('id', req.session.userId).single();
    res.json({ ...user, isActive: user.is_active });
});

// Rotas Administrativas
app.get('/api/admin/users', isAdmin, async (req, res) => {
    const { data: users } = await supabase.from('users').select('id, name, email, role, is_active').order('created_at', { ascending: false });
    // Mapear is_active para isActive para manter compatibilidade com o frontend atual
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

app.listen(PORT, () => {
    console.log(`🚀 AuraKnow Vercel Edition rodando na porta ${PORT}`);
});
