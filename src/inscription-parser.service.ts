import { OP_0, OP_ENDIF, encodeToBase64, getNextInscriptionMark, hexStringToUint8Array, knownFields, readPushdata, uint8ArrayToSingleByteChars, uint8ArrayToUtf8String } from "./inscription-parser.service.helper";
import { ParsedInscription } from "./parsed-inscription";


// private pointer = 0;
// private raw: Uint8Array = new Uint8Array();


/**
 * Extracts the first inscription from a Bitcoin transaction.
 * Advanced envelopes with extra data (eg Quadkey inscriptions) are supported, but the extra data is ignored.
 */
export class InscriptionParserService {

  /**
   * Main function that parses all inscription in a transaction.
   * @returns The parsed inscriptions or an empty array
   */
  static parseInscriptions(transaction: { vin: { witness?: string[] }[] }): ParsedInscription[] {

    const inscriptions: ParsedInscription[] = [];
    for (let i = 0; i < transaction.vin.length; i++) {
      const vin = transaction.vin[i];
      if (vin.witness) {
        const vinInscriptions = InscriptionParserService.parseInscriptionsWithinWitness(vin.witness);
        if (vinInscriptions) {
          inscriptions.push(...vinInscriptions);
        }
      }
    }
    return inscriptions;
  }

  /**
   * Parses all inscriptions within a given witness.
   * @param witness - The witness data from a vin[i].
   * @returns An array of parsed inscriptions, or null if no valid inscriptions are found.
   */
  private static parseInscriptionsWithinWitness(witness: string[]): ParsedInscription[] | null {

    const inscriptions: ParsedInscription[] = [];
    const raw = hexStringToUint8Array(witness.join(''));
    let startPosition = 0;

    while (true) {
      const pointer = getNextInscriptionMark(raw, startPosition);
      if (pointer === -1) break; // No more inscriptions found

      // Parse the inscription at the current position
      const inscription = InscriptionParserService.extractInscriptionData(raw, pointer);
      if (inscription) {
        inscriptions.push(inscription);
      }

      // Update startPosition for the next iteration
      startPosition = pointer;
    }

    return inscriptions.length > 0 ? inscriptions : null;
  }

  /**
   * Extracts inscription data starting from the current pointer.
   * @param raw - The raw data to read.
   * @param pointer - The current pointer where the reading starts.
   * @returns The parsed inscription or null
   */
  private static extractInscriptionData(raw: Uint8Array, pointer: number): ParsedInscription | null {

    let current: { slice: Uint8Array, pointer: number } = { slice: new Uint8Array(), pointer };

    try {

      // Process fields until OP_0 is encountered
      const fields: { tag: Uint8Array; value: Uint8Array }[] = [];
      while (current.pointer < raw.length && raw[current.pointer] !== OP_0) {

        current = readPushdata(raw, current.pointer);
        const tag = current.slice;

        current = readPushdata(raw, current.pointer);
        const value = current.slice;

        fields.push({ tag, value });
      }

      // Now we are at the beginning of the body
      // (or at the end of the raw data if there's no body)
      // --> Question: should we allow empty inscriptions? (where the next byte is OP_ENDIF)
      // --> TODO: Research what is ord doing in this edge case!
      if (current.pointer < raw.length && raw[current.pointer] === OP_0) {
        current = { slice: new Uint8Array(), pointer: current.pointer + 1 }; // skip OP_0
      }

      // Collect body data until OP_ENDIF
      const data: Uint8Array[] = [];
      while (current.pointer < raw.length && raw[current.pointer] !== OP_ENDIF) {
        current = readPushdata(raw, current.pointer);
        data.push(current.slice);
      }

      const combinedLengthOfAllArrays = data.reduce((acc, curr) => acc + curr.length, 0);
      const combinedData = new Uint8Array(combinedLengthOfAllArrays);

      // Copy all segments from data into combinedData, forming a single contiguous Uint8Array
      let idx = 0;
      for (const segment of data) {
        combinedData.set(segment, idx);
        idx += segment.length;
      }

      const contentTypeField = fields.find(x => x.tag.length === 1 && x.tag[0] === knownFields.content_type);

      // Let's ignore inscriptions without a contentType, because there is no good way to display them
      // we could change this later on, if there are really inscriptions with no contentType but meaningful metadata
      if (!contentTypeField) {
        return null;
      }

      // it would make no sense to add UTF-8 to content-type, so no UTF-8 here
      const contentType = uint8ArrayToSingleByteChars(contentTypeField.value);

      return {
        contentType,

        fields,

        getContentString() {
          return uint8ArrayToUtf8String(combinedData);
        },

        getData: (): string => {
          const content = uint8ArrayToSingleByteChars(combinedData);
          return encodeToBase64(content);
        },

        getDataUri: (): string => {
          const content = uint8ArrayToSingleByteChars(combinedData);
          const fullBase64Data = encodeToBase64(content);
          return `data:${contentType};base64,${fullBase64Data}`;
        }
      };

    } catch (ex) {
      console.error(ex);
      return null;
    }
  }
}
