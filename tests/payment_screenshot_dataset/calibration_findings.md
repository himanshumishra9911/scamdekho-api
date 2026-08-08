# Calibration findings: genuine payment screenshots

The first intake contains 16 user-confirmed genuine screenshots from 7 app
families and 8 independent transaction groups. These examples are calibration
data, not an accuracy test.

## Generalizable false-positive risks observed

- One real payment can appear as a full details page, a compact confirmation,
  or a share receipt with a substantially different layout.
- Cropped screens, image-viewer margins, OS status bars, and share UI can surround
  an otherwise genuine receipt.
- Ads, cashback, rewards, location cards, and promotional panels can occupy most
  of a genuine confirmation screen.
- Dark mode, decorative typography, highly minimal receipts, and very tall
  receipts are all legitimate presentation variants.
- UPI IDs and account numbers may be fully visible, partly masked, or heavily
  masked with asterisks.
- A payer app can show the recipient's app or handle branding. Cross-app branding
  is expected in interoperable UPI flows.
- Reference identifiers vary by provider: numeric, long numeric, or alphanumeric.
  Length or format alone is not authenticity evidence.
- The device status-bar time may differ from the transaction time because a
  receipt can be opened or shared later.

## Detector changes derived from the intake

- Treat all presentation variants above as benign unless a separate localized
  manipulation artifact is visible.
- Do not use remembered app templates as a whitelist. App/version/theme/language
  mismatches are weak evidence at most.
- Keep payment state, screenshot pixel authenticity, and risky payment context as
  separate outputs.
- Require strong localized evidence for a `SCAM` verdict. When the independent
  review disagrees, return `SUSPICIOUS` rather than forcing a binary answer.

## Remaining measurement gap

There are no fake examples and no untouched holdout examples in this intake.
The 95% target therefore cannot yet be measured without manufacturing a biased
test. Final evaluation needs independent genuine and fake screenshots from
different transactions, devices, app versions, and manipulation methods.
