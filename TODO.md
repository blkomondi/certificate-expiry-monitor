# Fix: Email Not Sending

## Root Cause
`load_dotenv()` is never called in the main CLI flow, so `.env` file variables are never loaded.

## Steps

- [x] Step 1: Investigate and plan
- [x] Step 2: Edit `checker/cli.py` — Add `load_dotenv()` import and call in `main()`
- [x] Step 3: Create `.env.example` template file
- [x] Step 4: Review and verify changes are correct
- [x] Step 5: All changes complete

