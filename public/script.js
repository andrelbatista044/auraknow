document.addEventListener('DOMContentLoaded', () => {
    // Carousel Logic
    const track = document.getElementById('carouselTrack');
    const nextBtn = document.getElementById('nextBtn');
    const prevBtn = document.getElementById('prevBtn');
    
    if (track && nextBtn && prevBtn) {
        let index = 0;
        const cardWidth = 470; // card min-width (420) + gap (50)
        const maxIndex = track.children.length - 1;

        nextBtn.addEventListener('click', () => {
            if (index < maxIndex) {
                index++;
                updateCarousel();
            } else {
                index = 0; // Loop back
                updateCarousel();
            }
        });

        prevBtn.addEventListener('click', () => {
            if (index > 0) {
                index--;
                updateCarousel();
            } else {
                index = maxIndex; // Loop to end
                updateCarousel();
            }
        });

        function updateCarousel() {
            const offset = index * cardWidth;
            track.style.transform = `translateX(-${offset}px)`;
        }

        // Responsive adjustment
        window.addEventListener('resize', () => {
            index = 0;
            updateCarousel();
        });
    }

    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });

    // Members Area interactivity
    const lessonItems = document.querySelectorAll('.lesson-item');
    const videoPlaceholder = document.querySelector('.video-container span');
    const lessonTitle = document.querySelector('.main-content h1');

    lessonItems.forEach(item => {
        item.addEventListener('click', () => {
            // Remove active class from all
            lessonItems.forEach(i => i.classList.remove('active'));
            
            // Add active class to clicked
            item.classList.add('active');

            // Update content (UI feedback)
            if (lessonTitle) {
                lessonTitle.innerText = item.innerText;
            }
            if (videoPlaceholder) {
                videoPlaceholder.innerText = `[ Carregando: ${item.innerText} ]`;
                setTimeout(() => {
                    videoPlaceholder.innerText = `[ Player de Vídeo: ${item.innerText} ]`;
                }, 500);
            }
        });
    });

    // Reveal animations on scroll
    const observerOptions = {
        threshold: 0.1
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, observerOptions);

    document.querySelectorAll('section, .glass').forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(30px)';
        el.style.transition = 'all 0.8s ease-out';
        observer.observe(el);
    });
});
