# gcs-pet-service-encryption

Service, that countains functionality to enc/dec String message using PGP

To have posibility to encrypt or decrypt message you need to put src/test/resources .asc files with public and private key
Public key we  are using for encryption and private for decryption. 
But for decryption you also need passPhrase for privateKey. You should add it to passPhrase field in PPGPServiceImpl class(com.efx.pet.service.encryption.impl)

After adding keys and passsPhrase, please open PGPServiceTest where you can put to clearMessage filed mesasge that you want to encrypt and start test.
In console you will see all steps, where you can find message after encryption and message after decryotion.

If you want only decrypt you message you can use decrypt test where you should add your enc message to String encMessage and start this test. In console you will see the resoult
if message was encrypted correctly with public key that was generated with you private key in resources folder


