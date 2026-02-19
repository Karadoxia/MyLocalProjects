import { Injectable } from '@nestjs/common';
import { CompatibilityCheckDto } from './dto/compatibility-check.dto';

@Injectable()
export class AgentService {
    private readonly marketIntel = `
  MARKET INTELLIGENCE REPORT Summary:
  1. The Market: E-com electronics growing to $1.22T by 2032. IT hardware $152B in 2026.
  2. Opportunity: Windows 10 PC Upgrade Tsunami. 500M PCs need replacement for Windows 11.
  3. Action: Create "Windows 11 Upgrade Hub".
  4. Suppliers: Tier 1 (Ingram Micro, Tech Data) for B2B. Tier 2 (CJ, Spocket) for automation.
  5. Strategy: Target SMB fleet replacements and Refurbished Windows 11 ready units.
  `;

    chat(message: string) {
        // Simple Keyword matching mock for the "Agent"
        const lowerMsg = message.toLowerCase();

        if (lowerMsg.includes('market') || lowerMsg.includes('opportunity')) {
            return {
                reply: "The biggest opportunity right now is the **Windows 10 Upgrade Tsunami**. There are 500 million PCs that need hardware replacement for Windows 11. We should focus on selling 'Windows 11 Ready' fleets to SMBs and refurbished units to consumers."
            };
        }

        if (lowerMsg.includes('supplier')) {
            return {
                reply: "For B2B hardware, we must target **Ingram Micro** and **Tech Data** to get real margins. For automation, CJdropshipping is our backup. Avoid generic AliExpress sourcing for high-ticket IT items."
            };
        }

        if (lowerMsg.includes('strategy') || lowerMsg.includes('plan')) {
            return {
                reply: "Our immediate plan: 1. Build the Windows 11 Compatibility Checker. 2. Secure Ingram Micro reseller account. 3. Launch SMB Fleet Upgrade packages. Speed is key!"
            };
        }

        return {
            reply: "I am your Strategic Advisor. Ask me about **market opportunities**, **suppliers**, or **strategy**."
        };
    }

    checkCompatibility(dto: CompatibilityCheckDto) {
        const reasons: string[] = [];
        let compatible = true;

        // Mock Logic based on Windows 11 requirements
        // CPU: 8th Gen Intel (approx 8000 series) or AMD Ryzen 2000
        // TPM: 2.0
        // RAM: 4GB+

        if (dto.tpmVersion < 2.0) {
            compatible = false;
            reasons.push("TPM 2.0 is required (Current: " + dto.tpmVersion + ")");
        }

        if (dto.ramGb < 4) {
            compatible = false;
            reasons.push("Minimum 4GB RAM required (Current: " + dto.ramGb + "GB)");
        }

        // Very basic CPU check simulation
        if (dto.cpu.toLowerCase().includes('i5-7') || dto.cpu.toLowerCase().includes('i7-7')) {
            compatible = false;
            reasons.push("CPU generation too old (Intel 7th Gen or older not supported)");
        }

        if (!compatible) {
            return {
                compatible: false,
                reasons,
                upgrade_suggestion: {
                    text: "Your PC is not ready for Windows 11. Check out our Certified Refurbished replacements.",
                    link: "/products?category=LAPTOP&tag=win11-ready"
                }
            };
        }

        return {
            compatible: true,
            message: "Your PC is Windows 11 Ready! No upgrade needed yet, but check our peripherals to boost productivity."
        };
    }
}
