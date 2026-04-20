const { supabase } = require('./db');
const bcrypt = require('bcryptjs');

async function createFirstAdmin() {
    const email = 'admin@auraknow.com';
    const password = 'admin123';
    const name = 'Administrador AuraKnow';

    const hashedPassword = await bcrypt.hash(password, 10);

    const { data, error } = await supabase
        .from('users')
        .insert([
            { name, email, password: hashedPassword, role: 'admin', is_active: true }
        ]);

    if (error) {
        console.error('❌ Erro ao criar admin:', error.message);
    } else {
        console.log('✅ Admin criado com sucesso: admin@auraknow.com / admin123');
    }
}

createFirstAdmin();
