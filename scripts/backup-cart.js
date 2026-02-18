const fs = require('fs').promises
const path = require('path')

const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(process.cwd(), 'data'))
const CART_FILE = process.env.CART_FILE || path.join(DATA_DIR, 'cart.json')
const BACKUP_DIR = path.join(process.cwd(), 'backups')

async function main(){
  try{
    await fs.mkdir(BACKUP_DIR, { recursive: true })
    const exists = await fs.stat(CART_FILE).then(() => true).catch(() => false)
    if(!exists){
      console.log('no cart to backup')
      return
    }
    const stamp = new Date().toISOString().replace(/[:.]/g,'-')
    const out = path.join(BACKUP_DIR, `cart-${stamp}.json`)
    await fs.copyFile(CART_FILE, out)
    console.log('backed up', CART_FILE, '→', out)
  }catch(err){
    console.error('backup failed', err)
    process.exit(1)
  }
}

main()
