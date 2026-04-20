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
        if (!user || !user.is_active) { res.clearCookie('token'); return res.status(403).json({ error: 'Bloqueado' }); }
        req.user = decoded;
        next();
    } catch (err) { res.clearCookie('token'); return res.status(401).json({ error: 'Sessão inválida' }); }
};

const isAdmin = async (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Não autorizado' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const { data: user } = await supabase.from('users').select('role, is_active').eq('id', decoded.id).single();
        if (user && user.role === 'admin' && user.is_active) { req.user = decoded; return next(); }
        res.status(403).json({ error: 'Acesso negado' });
    } catch (err) { res.clearCookie('token'); res.status(401).json({ error: 'Sessão inválida' }); }
};

// --- AUTH ---
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const { data: user } = await supabase.from('users').select('*').eq('email', email).single();
    if (!user) return res.status(404).json({ error: 'Não encontrado' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Senha incorreta' });
    const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none', maxAge: 7*24*60*60*1000 });
    res.json({ success: true, role: user.role });
});
app.post('/api/logout', (req, res) => { res.clearCookie('token'); res.json({ success: true }); });
app.get('/api/me', verifyToken, async (req, res) => {
    const { data: user } = await supabase.from('users').select('id, name, role, is_active').eq('id', req.user.id).single();
    res.json(user);
});

// --- NOTIFICAÇÕES ---
app.get('/api/me/notifications', verifyToken, async (req, res) => {
    const { data } = await supabase.from('notifications').select('*').eq('user_id', req.user.id).order('created_at', { ascending: false });
    res.json(data || []);
});
app.post('/api/me/notifications/:id/read', verifyToken, async (req, res) => {
    await supabase.from('notifications').update({ is_read: true }).eq('id', req.params.id).eq('user_id', req.user.id);
    res.json({ success: true });
});

// --- FINANCEIRO ---
app.get('/api/me/finance', verifyToken, async (req, res) => {
    const { data } = await supabase.from('payments').select('*').eq('user_id', req.user.id).order('due_date', { ascending: true });
    res.json(data || []);
});

// --- CURSOS / MATERIAS / MODULOS / AULAS (CRUD PADRÃO) ---
app.get('/api/courses', verifyToken, async (req, res) => {
    if (req.user.role === 'admin') {
        const { data } = await supabase.from('courses').select('*').order('created_at', { ascending: false });
        return res.json(data || []);
    }
    // Busca os IDs dos cursos matriculados
    const { data: enrollments, error: enrollError } = await supabase
        .from('enrollments')
        .select('course_id')
        .eq('user_id', req.user.id);

    if (enrollError) {
        console.error('Erro ao buscar matrículas:', enrollError);
        return res.json([]);
    }
    if (!enrollments || enrollments.length === 0) return res.json([]);

    // Busca os detalhes dos cursos pelos IDs
    const courseIds = enrollments.map(e => e.course_id);
    const { data: courses, error: coursesError } = await supabase
        .from('courses')
        .select('*')
        .in('id', courseIds);

    if (coursesError) {
        console.error('Erro ao buscar cursos:', coursesError);
        return res.json([]);
    }
    res.json(courses || []);
});

app.post('/api/admin/courses', isAdmin, async (req, res) => {
    const { data } = await supabase.from('courses').insert([req.body]).select();
    res.json(data[0]);
});
app.put('/api/admin/courses/:id', isAdmin, async (req, res) => { await supabase.from('courses').update(req.body).eq('id', req.params.id); res.json({ success: true }); });
app.delete('/api/admin/courses/:id', isAdmin, async (req, res) => { await supabase.from('courses').delete().eq('id', req.params.id); res.json({ success: true }); });

app.get('/api/courses/:id/subjects', verifyToken, async (req, res) => {
    const { data } = await supabase.from('subjects').select('*').eq('course_id', req.params.id).order('order', { ascending: true });
    res.json(data);
});
app.post('/api/admin/subjects', isAdmin, async (req, res) => {
    const { data } = await supabase.from('subjects').insert([req.body]).select();
    res.json(data[0]);
});
app.put('/api/admin/subjects/:id', isAdmin, async (req, res) => { await supabase.from('subjects').update(req.body).eq('id', req.params.id); res.json({ success: true }); });
app.delete('/api/admin/subjects/:id', isAdmin, async (req, res) => { await supabase.from('subjects').delete().eq('id', req.params.id); res.json({ success: true }); });

app.get('/api/subjects/:id/modules', verifyToken, async (req, res) => {
    const { data } = await supabase.from('modules').select('*').eq('subject_id', req.params.id).order('order', { ascending: true });
    res.json(data);
});
app.post('/api/admin/modules', isAdmin, async (req, res) => {
    const { data } = await supabase.from('modules').insert([req.body]).select();
    res.json(data[0]);
});
app.put('/api/admin/modules/:id', isAdmin, async (req, res) => { await supabase.from('modules').update(req.body).eq('id', req.params.id); res.json({ success: true }); });
app.delete('/api/admin/modules/:id', isAdmin, async (req, res) => { await supabase.from('modules').delete().eq('id', req.params.id); res.json({ success: true }); });

app.get('/api/modules/:id/lessons', verifyToken, async (req, res) => {
    const { data } = await supabase.from('lessons').select('*').eq('module_id', req.params.id).order('order', { ascending: true });
    res.json(data);
});
app.post('/api/admin/lessons', isAdmin, async (req, res) => {
    const { data } = await supabase.from('lessons').insert([req.body]).select();
    
    // Disparar notificação
    if (data && data[0]) {
        const lesson = data[0];
        const { data: mod } = await supabase.from('modules').select('subject_id').eq('id', lesson.module_id).single();
        if (mod && mod.subject_id) {
            const { data: sub } = await supabase.from('subjects').select('course_id').eq('id', mod.subject_id).single();
            if (sub && sub.course_id) {
                const { data: enrollments } = await supabase.from('enrollments').select('user_id').eq('course_id', sub.course_id);
                if (enrollments && enrollments.length > 0) {
                    const notifs = enrollments.map(e => ({
                        user_id: e.user_id,
                        title: 'Nova Aula',
                        message: `A aula "${lesson.title}" já está disponível.`,
                        type: 'lesson'
                    }));
                    await supabase.from('notifications').insert(notifs);
                }
            }
        }
    }
    
    res.json(data[0]);
});
app.put('/api/admin/lessons/:id', isAdmin, async (req, res) => { await supabase.from('lessons').update(req.body).eq('id', req.params.id); res.json({ success: true }); });
app.delete('/api/admin/lessons/:id', isAdmin, async (req, res) => { await supabase.from('lessons').delete().eq('id', req.params.id); res.json({ success: true }); });

// BUSCAR ÓRFÃOS
app.get('/api/courses/:id/orphan-modules', verifyToken, async (req, res) => {
    const { data } = await supabase.from('modules').select('*').eq('course_id', req.params.id).is('subject_id', null).order('order', { ascending: true });
    res.json(data);
});
app.get('/api/courses/:id/orphan-lessons', verifyToken, async (req, res) => {
    const { data } = await supabase.from('lessons').select('*').eq('course_id', req.params.id).is('module_id', null).order('order', { ascending: true });
    res.json(data);
});

// --- SISTEMA DE PROVAS (QUIZZES) ---
app.get('/api/modules/:id/quiz', verifyToken, async (req, res) => {
    const { data: quiz } = await supabase.from('quizzes').select('*').eq('module_id', req.params.id).single();
    if (!quiz) return res.json(null);
    const { data: questions } = await supabase.from('questions').select('id, text, options, order').eq('quiz_id', quiz.id).order('order', { ascending: true });
    res.json({ ...quiz, questions });
});

app.post('/api/admin/quizzes', isAdmin, async (req, res) => {
    const { module_id, title, passing_score, order, questions, due_date } = req.body;
    
    // UPSERT no Quiz (tenta atualizar pelo module_id ou insere novo)
    const { data: quiz, error: qErr } = await supabase.from('quizzes').upsert({ 
        module_id, 
        title, 
        passing_score, 
        order: order || 99,
        due_date: due_date || null
    }, { onConflict: 'module_id' }).select().single();

    if (qErr) return res.status(400).json({ error: qErr.message });

    if (questions && questions.length > 0) {
        // Se estiver editando, removemos as questões antigas para colocar as novas
        await supabase.from('questions').delete().eq('quiz_id', quiz.id);
        
        const questionsWithId = questions.map(q => ({ ...q, quiz_id: quiz.id }));
        await supabase.from('questions').insert(questionsWithId);
    }

    // Disparar notificação (Apenas se for novo? Por simplicidade deixaremos sempre por enquanto)
    // ... (restante do código de notificação permanece o mesmo)
    const { data: mod } = await supabase.from('modules').select('subject_id').eq('id', module_id).single();
    if (mod && mod.subject_id) {
        const { data: sub } = await supabase.from('subjects').select('course_id').eq('id', mod.subject_id).single();
        if (sub && sub.course_id) {
            const { data: enrollments } = await supabase.from('enrollments').select('user_id').eq('course_id', sub.course_id);
            if (enrollments && enrollments.length > 0) {
                const notifs = enrollments.map(e => ({
                    user_id: e.user_id,
                    title: 'Avaliação Atualizada',
                    message: `A prova "${title}" foi atualizada ou disponibilizada.`,
                    type: 'exam'
                }));
                await supabase.from('notifications').insert(notifs);
            }
        }
    }

    res.json({ success: true });
});

app.post('/api/quizzes/:id/submit', verifyToken, async (req, res) => {
    const { answers } = req.body; // { question_id: option_index }
    const { data: questions } = await supabase.from('questions').select('*').eq('quiz_id', req.params.id);
    const { data: quiz } = await supabase.from('quizzes').select('*').eq('id', req.params.id).single();
    
    // Verificar se o prazo expirou
    if (quiz.due_date && new Date() > new Date(quiz.due_date)) {
        return res.status(403).json({ error: 'O prazo para realizar esta prova expirou.' });
    }
    
    let correctCount = 0;
    questions.forEach(q => { if (answers[q.id] == q.correct_option) correctCount++; });
    const score = Math.round((correctCount / questions.length) * 100);
    const passed = score >= quiz.passing_score;

    await supabase.from('quiz_attempts').insert([{ user_id: req.user.id, quiz_id: quiz.id, score, passed }]);
    res.json({ score, passed });
});

app.get('/api/quiz-results', verifyToken, async (req, res) => {
    const { data } = await supabase.from('quiz_attempts').select('*, quizzes(title, module_id, passing_score)').eq('user_id', req.user.id).order('completed_at', { ascending: false });
    res.json(data);
});

app.get('/api/admin/all-results', isAdmin, async (req, res) => {
    const { data } = await supabase.from('quiz_attempts').select('*, users(name), quizzes(title)').order('completed_at', { ascending: false });
    res.json(data);
});

// --- USUÁRIOS ---
app.get('/api/admin/users', isAdmin, async (req, res) => {
    const { data } = await supabase.from('users').select('id, name, email, role, is_active, registration').order('created_at', { ascending: false });
    res.json(data.map(u => ({ ...u, isActive: u.is_active })));
});
app.post('/api/admin/create-user', isAdmin, async (req, res) => {
    if (req.body.registration) {
        const { data: existing } = await supabase.from('users').select('id').eq('registration', req.body.registration).single();
        if (existing) return res.status(400).json({ error: 'A matrícula informada já está em uso.' });
    }
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    await supabase.from('users').insert([{ ...req.body, password: hashedPassword }]);
    res.json({ success: true });
});
app.put('/api/admin/users/:id', isAdmin, async (req, res) => {
    const { name, email, role, registration } = req.body;
    if (registration) {
        const { data: existing } = await supabase.from('users').select('id').eq('registration', registration).single();
        if (existing && existing.id !== req.params.id) {
            return res.status(400).json({ error: 'A matrícula informada já está em uso por outro aluno.' });
        }
    }
    await supabase.from('users').update({ name, email, role, registration }).eq('id', req.params.id);
    res.json({ success: true });
});
app.post('/api/admin/toggle-status', isAdmin, async (req, res) => {
    const { data: user } = await supabase.from('users').select('is_active').eq('id', req.body.userId).single();
    await supabase.from('users').update({ is_active: !user.is_active }).eq('id', req.body.userId);
    res.json({ success: true });
});
app.delete('/api/admin/delete-user', isAdmin, async (req, res) => { await supabase.from('users').delete().eq('id', req.body.userId); res.json({ success: true }); });
app.post('/api/admin/enroll', isAdmin, async (req, res) => { 
    const { user_id, course_id } = req.body;
    if (!user_id || !course_id) return res.status(400).json({ error: 'user_id e course_id são obrigatórios' });
    await supabase.from('enrollments').insert([{ user_id, course_id }]); 
    res.json({ success: true }); 
});

// --- ADMIN FINANCEIRO ---
app.get('/api/admin/finance', isAdmin, async (req, res) => {
    const { data } = await supabase.from('payments').select('*, users(name)').order('due_date', { ascending: false });
    res.json(data || []);
});
app.post('/api/admin/finance', isAdmin, async (req, res) => {
    const { user_id, amount, due_date, status } = req.body;
    const { data, error } = await supabase.from('payments').insert([{ user_id, amount, due_date, status }]).select();
    if (error) return res.status(400).json({ error: error.message });
    
    // Disparar notificação
    await supabase.from('notifications').insert([{
        user_id,
        title: 'Novo Pagamento',
        message: `Uma nova fatura de R$ ${parseFloat(amount).toFixed(2)} foi gerada.`,
        type: 'finance'
    }]);

    res.json(data[0]);
});
app.put('/api/admin/finance/:id', isAdmin, async (req, res) => {
    const { error } = await supabase.from('payments').update(req.body).eq('id', req.params.id);
    if (error) return res.status(400).json({ error: error.message });
    res.json({ success: true });
});
app.delete('/api/admin/finance/:id', isAdmin, async (req, res) => {
    const { error } = await supabase.from('payments').delete().eq('id', req.params.id);
    if (error) return res.status(400).json({ error: error.message });
    res.json({ success: true });
});

// --- DEBUG TEMPORÁRIO ---
app.get('/api/debug/my-courses', verifyToken, async (req, res) => {
    const userId = req.user.id;
    const { data: enrollments } = await supabase.from('enrollments').select('*').eq('user_id', userId);
    const { data: allEnrollments } = await supabase.from('enrollments').select('*').limit(10);
    res.json({ 
        userId, 
        userRole: req.user.role,
        myEnrollments: enrollments, 
        allEnrollmentsSample: allEnrollments
    });
});

app.listen(PORT, () => console.log(`🚀 AuraKnow LMS v4 (Provas) na porta ${PORT}`));
