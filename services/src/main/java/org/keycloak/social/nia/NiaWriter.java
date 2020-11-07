package org.keycloak.social.nia;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamWriter;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.saml.processing.core.saml.v2.writers.BaseWriter;

public class NiaWriter extends BaseWriter {

    public NiaWriter(XMLStreamWriter writer) {
        super(writer);
    }

    public void writeSptype(NameIDType nameIDType, QName tag, boolean writeNamespace) throws ProcessingException {
        nameIDType.setValue("G");
        StaxUtil.writeStartElement(writer, "A", "B", "C");
        StaxUtil.writeNameSpace(writer, "A", "B");
        StaxUtil.writeAttribute(writer, "D", "E");
        write(nameIDType, new QName("F"), false);
        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }

}
