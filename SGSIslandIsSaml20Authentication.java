package utils;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.xml.XMLConstants;

import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.schema.impl.XSStringImpl;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * // Validates SAML 2.0 response from island.is Example usage: new
 * SGSIslandIsSaml20Authentication().validateSaml(islandIsToken, ip, userAgent,
 * authId);
 */

public class SGSIslandIsSaml20Authentication {

	// (friendly name „Kennitala“) inniheldur kennitölu notanda sem var að innskrá sig.
	public static final String SAML_ATTRIBUTE_USERSSN = "UserSSN";
	
	// (friendly name „Nafn“) inniheldur nafn notanda eins og það kemur fyrir í þjóðskrá eða fyrirtækjaskrá.
	public static final String SAML_ATTRIBUTE_NAME = "Name";
	
	// (friendly name „Auðkenning“) inniheldur auðkenningaraðferð not- anda. Breytan getur tekið eftirfarandi gildi í AUTHENTICATION_TYPE
	public static final String SAML_ATTRIBUTE_AUTHENTICATION = "Authentication";
	
	// (friendly name „VottunÍslykils“) fylgir með þegar notandi hefur innskráð sig með Íslykli eða styrktum Íslykli.
	public static final String SAML_ATTRIBUTE_KEYAUTHENTICATION = "KeyAuthentication";
	
	// (friendly name „IPTala“) inniheldur IP tölu notanda eins og hún birtist við innskráningu. Athugið að notandi getur haft aðra IP tölu gagnvart þjónustuveitanda en innskráningarkerfi svo ekki er hægt að treysta á hún sé sú sama og er í SAML tókanum.
	public static final String SAML_ATTRIBUTE_IPADDRESS = "IPAddress";
	
	// (friendly name „NotandaStrengur“) inniheldur upplýsingar um vafra notanda sem notaður var við auðkenningu. Dæmi um innihald er „Mozilla/5.0 (Windows NT 6.1; WOW64; rv:26.0) Gecko/20100101 Firefox/26.0“
	public static final String SAML_ATTRIBUTE_USERAGENT = "UserAgent";
	
	// (friendly name „KennitalaMóttakanda“) inniheldur kennitölu þjónustuveitanda.
	public static final String SAML_ATTRIBUTE_DESTINATIONSSN = "DestinationSSN";
	
	// (friendly name „AuðkenningarNúmer“) inniheldur einkvæmt númer sem þjónustuveitandi hefur sent með auðkenningarbeiðni. Ef þjónustuveitandi sendir ekkert þá birtist ekkert númer í svarinu.
	public static final String SAML_ATTRIBUTE_AUTHID = "AuthID";
	
	// (friendly name „KennitalaLögaðila“) fylgir með þegar notandi hefur innskráð sig með rafrænum starfsmannaskilríkjum eða styrktum rafrænum starfsmannaskilríkjum. Kennitala lögaðila er fengin úr starfsmannaskilríki notanda.
	public static final String SAML_ATTRIBUTE_COMPANYSSN = "CompanySSN";
	
	// (friendly name „NafnLögaðila“) fylgir með þegar notandi hefur innskráð sig með rafrænum starfsmannaskilríkjum eða styrktum rafrænum starfsmannaskilríkjum. Nafn lögaðila er fengin úr starfsmannaskilríki notanda.
	public static final String SAML_ATTRIBUTE_COMPANYNAME = "CompanyName";
	
	// SAML is valid from this time
	public static final String SAML_ATTRIBUTE_VALID_FROM = "SAMLNotBefore";
	
	// SAML is valid before this time
	public static final String SAML_ATTRIBUTE_VALID_TO = "SAMLNotOnOrAfter";
	
	// SAML Restricted audience
	public static final String SAML_ATTRIBUTE_AUDIENCE = "SAMLAudience";
	
	// iso 8601 datetime format used in the saml
	public static final SimpleDateFormat DATE_FORMAT_ISO8601 = new SimpleDateFormat("yyyy.MM.dd'T'hh:mm:ss");
	
	// Key in result map containing the complete saml text
	public static final String SAML_MAP_KEY = "saml20";
	
	private static final Logger logger = LoggerFactory.getLogger(SGSIslandIsSaml20Authentication.class);
	private static final String VALID_SUBJECT_DN = "SERIALNUMBER=6503760649"; // Þjóðskrá Íslands persidno
	private static final String 	 = "CN=Fullgilt audkenni";
	private final KeyStore _keystore;

	public enum KEY_AUTHENTICATION_TYPE {
		RAFRAEN_SKILRIKI("Rafræn skilríki", "notandi var innskráður með rafrænum skilríkjum þegar Íslykill var búinn til"),
		BREF_I_POSTI("Bréf í pósti", "notandi innskráði sig með Íslykli sendum á lögheimili einstaklings þegar Íslykill var búinn til"),
		SKJAL_I_HEIMABANKA("Skjal í heimabanka", "notandi innskráði sig með Íslykli sendum í heimabankabirtingu einstaklings þegar Íslykill var búinn til"),
		AFHENT_HJA_THJODSKRA("Afhent hjá Þjóðskrá gegn framvísun löggildra skilríkja", ""), AFHENT_HJA_SAMSTARFSADILA_THJODSKRA("Afhent hjá samstarfsaðila Þjóðskrár gegn framvísun löggildra skilríkja", ""),
		BREF_I_POSTI_TIL_SENDIRADS("Bréf í pósti á sendiráð og afhending gegng framvísun löggildra skilríkja", ""),
		OTHEKKT("Óþekkt", "þegar upplýsingar um það hvað af ofangreindu var notað við gerð Íslykils liggja ekki fyrir");

		private String _key;
		private String _expl;

		KEY_AUTHENTICATION_TYPE(String key, String expl) {
			this._key = key;
			this._expl = expl;
		}

		public static KEY_AUTHENTICATION_TYPE find(String key) {
			for (KEY_AUTHENTICATION_TYPE item : KEY_AUTHENTICATION_TYPE.values()) {
				if (item.key().equals(key)) {
					return item;
				}
			}
			return null;
		}

		public String key() {
			return this._key;
		}

		public String explanation() {
			return this._expl;
		}
	}

	public enum AUTHENTICATION_TYPE {
		RAFRAEN_SKILRIKI("Rafræn skilríki", "þegar notandi hefur innskráð sig með rafrænum skilríkjum"),
		RAFRAEN_STARFSMANNASKILRIKI("Rafræn starfsmannaskilríki", "þegar notandi hefur innskráð sig með rafrænum starfsmannaskilríkjum"), ISLYKILL("Íslykill", "þegar notandi hefur innskráð sig með Íslykli"),
		STYRKTUR_ISLYKILL("Styrktur Íslykill", "þegar notandi hefur innskráð sig með Íslykli og styrkingarkóða sendum í síma eða á netfang."),
		STYRKT_RAFRAEN_SKILRIKI("Styrkt rafræn skilríki", "þegar notandi hefur innskráð sig með rafrænum skilríkjum og styrkingarkóða sendum í síma eða á netfang."),
		STYRKT_RAFRAEN_STARFSMANNASKILRIKI("Styrkt rafræn starfsmannaskilríki", "þegar notandi hefur innskráð sig með rafrænum starfsmannaskilríkjum og styrkingarkóða sendum í síma eða netfang."),
		OTHEKKT("Óþekkt", "þegar innskráning er ekki þekkt (ekki notað – villa)");

		private String _key;
		private String _expl;

		AUTHENTICATION_TYPE(String key, String expl) {
			this._key = key;
			this._expl = expl;
		}

		public static AUTHENTICATION_TYPE find(String key) {
			for (AUTHENTICATION_TYPE item : AUTHENTICATION_TYPE.values()) {
				if (item.key().equals(key)) {
					return item;
				}
			}
			return null;
		}

		public String key() {
			return this._key;
		}

		public String explanation() {
			return this._expl;
		}
	}

	/**
	 * Takes in loaded keystore and performs initialization
	 * 
	 * @param jksKeyStore keystore to validate against
	 */
	public SGSIslandIsSaml20Authentication(KeyStore keystore) throws ConfigurationException {
		_keystore = keystore;
		DefaultBootstrap.bootstrap();
	}

	/**
	 * Validate certificate against CA chain in keystore
	 * 
	 * @param cert     Certificate to validate
	 * @param keystore containing the CA chain
	 * @return true if chain is valid
	 * @throws GeneralSecurityException if exception occurs while loading
	 *                                  certificate and/or keystore into validator
	 */
	public static boolean validateCertificateChain(Certificate cert, KeyStore keystore) throws GeneralSecurityException {
		List<Certificate> certx = new ArrayList<Certificate>(1);
		certx.add(cert);

		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		CertPath path = cf.generateCertPath(certx);
		CertPathValidator validator = CertPathValidator.getInstance("PKIX");

		PKIXParameters params = new PKIXParameters(keystore);
		params.setRevocationEnabled(true);
		Security.setProperty("ocsp.enable", "true"); // activate OCSP checking when validating the certificate path
		System.setProperty("com.sun.security.enableCRLDP", "true"); // fallback check for CRL if no OCSP is available

		/* Validate will throw an exception on invalid chains. */
		try {
			PKIXCertPathValidatorResult r = (PKIXCertPathValidatorResult) validator.validate(path, params);
			logger.debug("SAML certification passed validation against CA chain.");

		} catch (CertPathValidatorException | InvalidAlgorithmParameterException e) {
			return false;
		}
		return true;
	}

	/**
	 * validates a base64 encoded saml 2.0 message sent from island.is
	 * 
	 * @param samlString base64 encoded saml 2.0
	 * @param userIP
	 * @param userAgent
	 * @param authId
	 * @return if validation succeds a hash map with all attributes from the saml
	 *         2.0 message is returned else an exception is thrown
	 * @throws Exception if validation fails
	 */
	public Map<String, String> validateSaml(final String samlString, final String userIP, final String authId, final String restrictedAudience) throws Exception {
		Map<String, String> attributeMap = null;
		SignableSAMLObject signedObject = (SignableSAMLObject) this.unmarshall(samlString);
		if (signedObject != null) {
			SignableSAMLObject samlObject = (SignableSAMLObject) this.validateSignature(signedObject);
			if (samlObject != null) {
				Assertion assertion = this.getAssertion((Response) samlObject, userIP, false);
				if (assertion != null) {
					final DateTime serverDate = new DateTime();
					if (assertion.getConditions().getNotBefore().isAfter(serverDate)) {
						throw new Exception("Token date valid yet (getNotBefore = " + assertion.getConditions().getNotBefore() + " ), server_date: " + serverDate);
					}
					if (assertion.getConditions().getNotOnOrAfter().isBefore(serverDate)) {
						throw new Exception("Token date expired (getNotOnOrAfter = " + assertion.getConditions().getNotOnOrAfter() + " ), server_date: " + serverDate);
					}
					// Validate the assertions for IP, useragent and authId.
					attributeMap = fetchAssertionAttributes(assertion);
					attributeMap.put(SAML_ATTRIBUTE_VALID_FROM, DATE_FORMAT_ISO8601.format(assertion.getConditions().getNotBefore().toDate()));
					attributeMap.put(SAML_ATTRIBUTE_VALID_TO, DATE_FORMAT_ISO8601.format(assertion.getConditions().getNotOnOrAfter().toDate()));

					List<String> audienceList = new ArrayList<String>();
					for (AudienceRestriction restrictions : assertion.getConditions().getAudienceRestrictions()) {
						for (Audience audience : restrictions.getAudiences()) {
							audienceList.add(audience.getAudienceURI());
						}
					}
					if (Collections.binarySearch(audienceList, restrictedAudience) < 0) {
						throw new Exception("Restricted audience[" + restrictedAudience + "] not found in SAML[" + audienceList.stream().collect(Collectors.joining(",")) + "]");
					}
					attributeMap.put(SAML_ATTRIBUTE_AUDIENCE, audienceList.stream().collect(Collectors.joining(",")));

					attributeMap.put(SAML_MAP_KEY, samlString);
					validateAssertion(attributeMap, userIP, authId);
				}
			}
		}

		return attributeMap;
	}

	// Unmarshall SAML string
	private final XMLObject unmarshall(final String samlString) throws Exception {
		try {
			byte[] samlToken = Base64.getDecoder().decode(samlString);
			final BasicParserPool ppMgr = new BasicParserPool();
			final HashMap<String, Boolean> features = new HashMap<String, Boolean>();
			features.put(XMLConstants.FEATURE_SECURE_PROCESSING, Boolean.TRUE);
			ppMgr.setBuilderFeatures(features);
			ppMgr.setNamespaceAware(true);
			Document document = ppMgr.parse(new ByteArrayInputStream(samlToken));
			if (document != null) {
				final Element root = document.getDocumentElement();
				final UnmarshallerFactory unmarshallerFact = Configuration.getUnmarshallerFactory();
				if (unmarshallerFact != null && root != null) {
					final Unmarshaller unmarshaller = unmarshallerFact.getUnmarshaller(root);
					try {
						return unmarshaller.unmarshall(root);
					} catch (NullPointerException e) {
						throw new Exception("NullPointerException", e);
					}
				} else {
					throw new Exception("NullPointerException : unmarshallerFact or root is null");
				}
			} else {
				throw new Exception("NullPointerException : document is null");
			}
		} catch (XMLParserException e) {
			throw new Exception(e);
		} catch (UnmarshallingException e) {
			throw new Exception(e);
		} catch (NullPointerException e) {
			throw new Exception(e);
		}
	}

	// validate the saml signature
	private final SAMLObject validateSignature(final SignableSAMLObject tokenSaml) throws SignatureException {

		// Indicates signature id conform to SAML Signature profile
		final SAMLSignatureProfileValidator sigProfValidator = new SAMLSignatureProfileValidator();
		try {
			sigProfValidator.validate(tokenSaml.getSignature());
		} catch (ValidationException e) {
			throw new SignatureException(e);
		}

		try {
			final KeyInfo keyInfo = tokenSaml.getSignature().getKeyInfo();
			final org.opensaml.xml.signature.X509Certificate xmlCert = keyInfo.getX509Datas().get(0).getX509Certificates().get(0);
			final CertificateFactory certFact = CertificateFactory.getInstance("X.509");
			final ByteArrayInputStream bis = new ByteArrayInputStream(Base64.getDecoder().decode(xmlCert.getValue()));
			final X509Certificate xmlCertificate = (X509Certificate) certFact.generateCertificate(bis);
			final BasicX509Credential entityX509Cred = new BasicX509Credential();
			entityX509Cred.setEntityCertificate(xmlCertificate);
			xmlCertificate.checkValidity();

			// Validate saml certificate against CA chain in keystore
			if (!validateCertificateChain(xmlCertificate, _keystore)) {
				throw new SignatureException("SAML certificate failed validation.");
			}

			BasicX509Credential publicCredential = new BasicX509Credential();
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(xmlCertificate.getPublicKey().getEncoded());
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey key = keyFactory.generatePublic(publicKeySpec);
			if (key != null) {
				publicCredential.setPublicKey(key);
				SignatureValidator signatureValidator = new SignatureValidator(publicCredential);
				try {
					signatureValidator.validate(tokenSaml.getSignature());
				} catch (ValidationException ve) {
					throw new SignatureException("SAML signature is not trusted.");
				}
			}

			if (!xmlCertificate.getSubjectDN().toString().contains(VALID_SUBJECT_DN)) {
				throw new SignatureException("Certificate subject[" + xmlCertificate.getSubjectDN().toString() + "] does not contain " + VALID_SUBJECT_DN);
			} else if (!xmlCertificate.getIssuerDN().toString().contains(VALID_ISSUER_DN_START_VALUE)) {
				throw new SignatureException("Certificate issuer[" + xmlCertificate.getIssuerDN().toString() + "] does not contain " + VALID_ISSUER_DN_START_VALUE);
			}
		} catch (CertificateException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new SignatureException(e);
		} catch (GeneralSecurityException e) {
			throw new SignatureException(e);
		}

		return tokenSaml;
	}

	private Assertion getAssertion(final Response samlResponse, final String userIP, final boolean ipValidate) throws Exception {
		if (samlResponse.getAssertions() == null || samlResponse.getAssertions().isEmpty()) {
			// Assertion is null or empty
			return null;
		}
		final Assertion assertion = (Assertion) samlResponse.getAssertions().get(0);
		for (final Iterator<SubjectConfirmation> iter = assertion.getSubject().getSubjectConfirmations().iterator(); iter.hasNext();) {
			final SubjectConfirmation element = iter.next();
			final boolean isBearer = SubjectConfirmation.METHOD_BEARER.equals(element.getMethod());
			if (ipValidate) {
				if (isBearer) {
					if (isBlank(userIP)) {
						throw new Exception("browser_ip is null or empty.");
					} else if (isBlank(element.getSubjectConfirmationData().getAddress())) {
						throw new Exception("token_ip attribute is null or empty.");
					}
				}
				final boolean ipEqual = element.getSubjectConfirmationData().getAddress().equals(userIP);
				// Validation ipUser
				if (!ipEqual && ipValidate) {
					throw new Exception("IPs doesn't match : token_ip (" + element.getSubjectConfirmationData().getAddress() + ") browser_ip (" + userIP + ")");
				}

			}
		}
		return assertion;
	}

	private boolean isBlank(String str) {
		return ((str == null) || str.trim().length() < 1);
	}

	/**
	 * Validate that attributes are precent and returns them in a hashmap
	 * 
	 * @param assertion The assertion to parse
	 * @throws Exception if no attributes are found
	 */
	private Map<String, String> fetchAssertionAttributes(final Assertion assertion) throws Exception {
		final List<XMLObject> listExtensions = assertion.getOrderedChildren();
		boolean find = false;
		AttributeStatement requestedAttr = null;
		// Search the attribute statement.
		for (int i = 0; i < listExtensions.size() && !find; i++) {
			final XMLObject xml = listExtensions.get(i);
			if (xml instanceof AttributeStatement) {
				requestedAttr = (AttributeStatement) xml;
				find = true;
			}
		}
		if (!find) {
			throw new Exception("AttributeStatement it's not present.");
		}
		final List<Attribute> reqAttrs = requestedAttr.getAttributes();
		String attributeName, tempValue;
		XMLObject xmlObj;
		// Process the attributes.
		Map<String, String> attributeMap = new HashMap<String, String>();
		for (int nextAttribute = 0; nextAttribute < reqAttrs.size(); nextAttribute++) {
			final Attribute attribute = reqAttrs.get(nextAttribute);
			attributeName = attribute.getName();
			xmlObj = attribute.getOrderedChildren().get(0);
			tempValue = ((XSStringImpl) xmlObj).getValue();

			attributeMap.put(attributeName, tempValue);
		}
		return attributeMap;
	}

	/**
	 * Validate assertions for IP, user agent and auth ID
	 * 
	 * @param ip     The user IP
	 * @param ua     The users user agent
	 * @param authId The auth ID, if null then this attribute is not validated
	 * @throws Exception
	 */
	private void validateAssertion(final Map<String, String> attributeMap, String ip, String authId) throws Exception {
		boolean ipOk = (ip == null), authIdOk = (authId == null);
		for (Map.Entry<String, String> entry : attributeMap.entrySet()) {
			if ((ip != null) && SAML_ATTRIBUTE_IPADDRESS.equals(entry.getKey())) {
				logger.debug(SAML_ATTRIBUTE_IPADDRESS + ": " + entry.getValue());
				ipOk = (entry.getValue() != null) && entry.getValue().equals(ip);
			}
			if ((authId != null) && SAML_ATTRIBUTE_AUTHID.equals(entry.getKey())) {
				// does not validate authId if its not provided by host
				authIdOk = (authId == null) || (entry.getValue() != null) && entry.getValue().equals(authIdOk);
				logger.debug(SAML_ATTRIBUTE_AUTHID + ": " + entry.getValue());
			}
		}
		if (ipOk && authIdOk)
			logger.debug("Assertion valid.");
		else
			throw new Exception(String.format("Assertions not valid. IP valid %b, auth ID valid %b", ipOk, authIdOk));
	}
}
