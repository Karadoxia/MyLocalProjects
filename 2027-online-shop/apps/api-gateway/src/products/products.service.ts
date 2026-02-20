import { Injectable, OnModuleInit, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { Prisma } from '@prisma/client';

const CATALOG: Prisma.ProductCreateInput[] = [
  // ─── Peripherals ─────────────────────────────────────────────
  {
    sku: 'NEXUS-NLI-001', title: 'Neural Link Interface v4', category: 'PERIPHERAL',
    description: 'Sub-millisecond latency brain-computer interface with wireless 6G connectivity and adaptive haptic feedback.',
    price: 899, supplierPrice: 450, status: 'ACTIVE',
    images: JSON.stringify(['https://images.unsplash.com/photo-1518770660439-4636190af475?w=800&q=80']),
  },
  {
    sku: 'NEXUS-MKB-001', title: 'Holographic Mechanical Keyboard', category: 'PERIPHERAL',
    description: 'Full-size mechanical keyboard with holographic key display, per-key RGB, and tactile optical switches.',
    price: 299, supplierPrice: 140, status: 'ACTIVE',
    images: JSON.stringify(['https://images.unsplash.com/photo-1587829741301-dc798b83add3?w=800&q=80']),
  },
  {
    sku: 'NEXUS-MSE-001', title: 'Quantum Precision Mouse 8K', category: 'PERIPHERAL',
    description: '8000 DPI optical sensor, 1ms polling rate, aircraft-grade aluminium shell. Zero-delay wireless.',
    price: 149, supplierPrice: 70, status: 'ACTIVE',
    images: JSON.stringify(['https://images.unsplash.com/photo-1527864550417-7fd91fc51a46?w=800&q=80']),
  },
  {
    sku: 'NEXUS-HDT-001', title: 'Neuro-Haptic Headset Pro', category: 'PERIPHERAL',
    description: 'Spatial audio headset with haptic transducers and bone conduction, 72h battery, AI noise cancellation.',
    price: 549, supplierPrice: 260, status: 'ACTIVE',
    images: JSON.stringify(['https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=800&q=80']),
  },
  // ─── Laptops ─────────────────────────────────────────────────
  {
    sku: 'NEXUS-CDK-001', title: 'Cyberdeck Portable MK.II', category: 'LAPTOP',
    description: 'Ruggedized field laptop — military-grade chassis, mechanical keys, satellite link module, 72h battery.',
    price: 1250, supplierPrice: 700, status: 'ACTIVE',
    images: JSON.stringify(['https://images.unsplash.com/photo-1496181133206-80ce9b88a853?w=800&q=80']),
  },
  {
    sku: 'NEXUS-ULT-001', title: 'UltraSlate X1 — 14" Creator', category: 'LAPTOP',
    description: '14" OLED 120Hz display, 36-core neural CPU, 64 GB LPDDR6, 4 TB NVMe. 1.1 kg carbon fibre.',
    price: 2800, supplierPrice: 1700, status: 'ACTIVE',
    images: JSON.stringify(['https://images.unsplash.com/photo-1517430816045-df4b7de11d1d?w=800&q=80']),
  },
  // ─── Workstations / Desktops ─────────────────────────────────
  {
    sku: 'NEXUS-QCW-001', title: 'Quantum Core Workstation', category: 'WORKSTATION',
    description: '128-qubit-accelerated workstation with holographic projector, liquid cooling, and 1 PB SSD array.',
    price: 4500, supplierPrice: 2800, status: 'ACTIVE',
    images: JSON.stringify(['https://images.unsplash.com/photo-1547082299-de196ea013d6?w=800&q=80']),
  },
  {
    sku: 'NEXUS-TWR-001', title: 'Titan Tower R9 Workstation', category: 'WORKSTATION',
    description: 'Dual-socket workstation: 2× 96-core CPUs, 512 GB ECC RAM, RTX 9090 Ti, custom water cooling loop.',
    price: 8900, supplierPrice: 5400, status: 'ACTIVE',
    images: JSON.stringify(['https://images.unsplash.com/photo-1591799264318-7e6ef8ddb7ea?w=800&q=80']),
  },
  // ─── Monitors ────────────────────────────────────────────────
  {
    sku: 'NEXUS-MON-001', title: 'HoloView 32" 8K HDR Monitor', category: 'MONITOR',
    description: '32" 8K OLED panel, 240Hz, 0.03ms GTG, DisplayHDR 2000, DCI-P3 99%, factory calibrated.',
    price: 1900, supplierPrice: 1050, status: 'ACTIVE',
    images: JSON.stringify(['https://images.unsplash.com/photo-1527443224154-c4a3942d3acf?w=800&q=80']),
  },
  {
    sku: 'NEXUS-MON-002', title: 'UltraWide 49" Curved Command Center', category: 'MONITOR',
    description: '49" 5120×1440 curved VA panel, 165Hz, HDR1000, KVM built-in, USB-C 140W PD.',
    price: 1199, supplierPrice: 650, status: 'ACTIVE',
    images: JSON.stringify(['https://images.unsplash.com/photo-1620288627223-53302f4e8c74?w=800&q=80']),
  },
  // ─── Networking ───────────────────────────────────────────────
  {
    sku: 'NEXUS-ODN-001', title: 'Optical Data Node', category: 'NETWORK',
    description: '100 Gbps mesh-compatible networking node with Zero-Trust OS and quantum-encrypted data plane.',
    price: 349, supplierPrice: 180, status: 'ACTIVE',
    images: JSON.stringify(['https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=800&q=80']),
  },
  {
    sku: 'NEXUS-RT6-001', title: 'WiFi 7 Triband Mesh Router Pro', category: 'NETWORK',
    description: 'Wi-Fi 7 (BE19000) triband, 10 Gbps WAN, built-in IDS/IPS, 1 km² coverage with 3 nodes.',
    price: 599, supplierPrice: 310, status: 'ACTIVE',
    images: JSON.stringify(['https://images.unsplash.com/photo-1606904825846-647eb07f5be2?w=800&q=80']),
  },
  // ─── Storage ─────────────────────────────────────────────────
  {
    sku: 'NEXUS-SSD-001', title: 'HyperDrive 4 TB PCIe 5.0 NVMe', category: 'STORAGE',
    description: '4 TB PCIe 5.0 NVMe SSD — 14 GB/s sequential read, 256-bit AES hardware encryption, 5-year warranty.',
    price: 429, supplierPrice: 210, status: 'ACTIVE',
    images: JSON.stringify(['https://images.unsplash.com/photo-1598300042247-d088f8ab3a91?w=800&q=80']),
  },
  {
    sku: 'NEXUS-NAS-001', title: 'Vault Pro 8-Bay NAS Enclosure', category: 'STORAGE',
    description: '8-bay NAS, 10 GbE dual-port, hot-swap SAS/SATA, RAID 0/1/5/6/10, self-encrypting drives.',
    price: 1450, supplierPrice: 780, status: 'ACTIVE',
    images: JSON.stringify(['https://images.unsplash.com/photo-1531492746076-161ca9bcad58?w=800&q=80']),
  },
  // ─── Components ──────────────────────────────────────────────
  {
    sku: 'NEXUS-GPU-001', title: 'RTX 9090 Ultra — 48 GB GDDR8', category: 'COMPONENT',
    description: '48 GB GDDR8 flagship GPU with 4th-gen RT cores, dual 16-pin power, AI-assisted overclocking.',
    price: 2399, supplierPrice: 1400, status: 'ACTIVE',
    images: JSON.stringify(['https://images.unsplash.com/photo-1591488320449-011701bb6704?w=800&q=80']),
  },
  {
    sku: 'NEXUS-CPU-001', title: 'Helix X1 96-Core Processor', category: 'COMPONENT',
    description: '96 performance cores + 32 efficiency cores, 5 nm, 192 MB L3 cache, PCIe 6.0 x64, 350 W TDP.',
    price: 1799, supplierPrice: 1000, status: 'ACTIVE',
    images: JSON.stringify(['https://images.unsplash.com/photo-1555617766-d48dff1f6de2?w=800&q=80']),
  },
  // ─── Accessories ─────────────────────────────────────────────
  {
    sku: 'NEXUS-DSK-001', title: 'Carbon Fibre Smart Desk Mat XL', category: 'ACCESSORY',
    description: 'XXL 90×45 cm desk mat with wireless charging zones, USB-A/C hub, and ambient light strip.',
    price: 129, supplierPrice: 55, status: 'ACTIVE',
    images: JSON.stringify(['https://images.unsplash.com/photo-1611532736597-de2d4265fba3?w=800&q=80']),
  },
  {
    sku: 'NEXUS-WBK-001', title: 'ErgoArm Dual Monitor Mount', category: 'ACCESSORY',
    description: 'Gas-spring dual monitor arm, 10 kg per arm, cable management, VESA 75/100, 360° rotation.',
    price: 189, supplierPrice: 85, status: 'ACTIVE',
    images: JSON.stringify(['https://images.unsplash.com/photo-1593640408182-31c228b9a6a4?w=800&q=80']),
  },
  {
    sku: 'NEXUS-CAM-001', title: 'StreamCam 4K AI Webcam', category: 'ACCESSORY',
    description: '4K 60fps webcam with AI background segmentation, eye-contact correction, ring light, and Sony Starvis sensor.',
    price: 249, supplierPrice: 110, status: 'ACTIVE',
    images: JSON.stringify(['https://images.unsplash.com/photo-1587826080692-f439cd0b70da?w=800&q=80']),
  },
  {
    sku: 'NEXUS-USB-001', title: 'Thunderbolt 4 Hub — 18-in-1', category: 'ACCESSORY',
    description: 'Thunderbolt 4 hub with 2× 8K outputs, 3× USB-C 40 Gbps, SD 8.0, 2.5 GbE, 140W PD pass-through.',
    price: 219, supplierPrice: 95, status: 'ACTIVE',
    images: JSON.stringify(['https://images.unsplash.com/photo-1625842268584-8f3296236761?w=800&q=80']),
  },
];

@Injectable()
export class ProductsService implements OnModuleInit {
  private readonly logger = new Logger(ProductsService.name);

  constructor(private prisma: PrismaService) { }

  async onModuleInit() {
    const count = await this.prisma.product.count();
    if (count < CATALOG.length) {
      this.logger.log(`Catalog has ${count}/${CATALOG.length} products — syncing missing entries...`);
      let added = 0;
      for (const product of CATALOG) {
        await this.prisma.product.upsert({
          where: { sku: product.sku as string },
          create: product,
          update: {
            title: product.title,
            description: product.description,
            price: product.price,
            supplierPrice: product.supplierPrice,
            images: product.images,
            category: product.category,
            status: product.status,
          },
        });
        added++;
      }
      this.logger.log(`Catalog sync complete — ${added} products upserted.`);
    } else {
      this.logger.log(`Catalog OK: ${count} products in DB.`);
    }
  }

  async create(createProductDto: any) {
    return this.prisma.product.create({ data: createProductDto });
  }

  async addProduct(product: Prisma.ProductCreateInput) {
    return this.prisma.product.create({ data: product });
  }

  async findAll() {
    return this.prisma.product.findMany();
  }

  async findOne(id: string) {
    return this.prisma.product.findUnique({ where: { id } });
  }

  async update(id: string, updateProductDto: any) {
    return this.prisma.product.update({ where: { id }, data: updateProductDto });
  }

  async remove(id: string) {
    return this.prisma.product.delete({ where: { id } });
  }
}
