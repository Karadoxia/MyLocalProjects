const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function main() {
    console.log('Cleaning up imported products...');
    const { count } = await prisma.product.deleteMany({
        where: {
            name: {
                startsWith: 'Imported',
            },
        },
    });
    console.log(`Deleted ${count} imported products.`);
}

main()
    .catch((e) => {
        console.error(e);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });
