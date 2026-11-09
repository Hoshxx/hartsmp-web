module.exports = {
    content: ['./index.html'],
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Inter', 'sans-serif'],
                        heading: ['Poppins', 'sans-serif'],
                    },
                    colors: {
                        slate: {
                            850: '#1e293b',
                            900: '#0f172a',
                            950: '#0b0f19', // Deep slate requested
                        },
                        discord: '#5865F2',
                        discordHover: '#4752C4'
                    },
                    backgroundImage: {
                        'hero-pattern': "linear-gradient(to bottom, rgba(11, 15, 25, 0.7), rgba(11, 15, 25, 1)), url('/assets/hero.jpg')",
                    }
                }
            }
        }
